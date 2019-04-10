/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

// TODO(antonin): define mutex wrapper class in separate file?
#ifdef USE_ABSL
#include "absl/synchronization/mutex.h"
#else
// shared mutex not available in C++11
#include <boost/thread/shared_mutex.hpp>
#endif

#include <PI/frontends/cpp/tables.h>
#include <PI/frontends/proto/device_mgr.h>
#include <PI/pi.h>
#include <PI/proto/util.h>

#include <cstdio>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>  // for std::pair
#include <vector>

#include "google/rpc/code.pb.h"

#include "action_helpers.h"
#include "action_prof_mgr.h"
#include "common.h"
#include "digest_mgr.h"
#include "idle_timeout_buffer.h"
#include "match_key_helpers.h"
#include "packet_io_mgr.h"
#include "pre_clone_mgr.h"
#include "pre_mc_mgr.h"
#include "report_error.h"
#include "statusor.h"
#include "table_info_store.h"

#include "p4/tmp/p4config.pb.h"
#include "PI/proto/p4info_to_and_from_proto.h"  // for p4info_proto_reader

namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;
using p4configv1::P4Ids;

namespace pi {

namespace fe {

namespace proto {

using device_id_t = DeviceMgr::device_id_t;
using p4_id_t = common::p4_id_t;
using Status = DeviceMgr::Status;
using StreamMessageResponseCb = DeviceMgr::StreamMessageResponseCb;
using Code = ::google::rpc::Code;
using common::SessionTemp;
using common::check_proto_bytestring;
using common::make_invalid_p4_id_status;

// We don't yet have a mapping from PI error codes to ::google::rpc::Code
// values, so for now we almost always return UNKNOWN. It is likely that we will
// have our own error namespace (in addition to ::google::rpc::Code) anyway.

namespace {

#ifdef USE_ABSL

// The absl versions delete the default move constructor and default move
// assignment operator, so I define my own versions here.
class SCOPED_LOCKABLE ReaderMutexLock {
 public:
  explicit ReaderMutexLock(absl::Mutex *mu) SHARED_LOCK_FUNCTION(mu)
      :  mu_(mu) {
    mu->ReaderLock();
  }

  ReaderMutexLock(const ReaderMutexLock&) = delete;
  ReaderMutexLock(ReaderMutexLock&&) = default;
  ReaderMutexLock& operator=(const ReaderMutexLock&) = delete;
  ReaderMutexLock& operator=(ReaderMutexLock&&) = default;

  ~ReaderMutexLock() UNLOCK_FUNCTION() {
    this->mu_->ReaderUnlock();
  }

 private:
  absl::Mutex *const mu_;
};

class SCOPED_LOCKABLE WriterMutexLock {
 public:
  explicit WriterMutexLock(absl::Mutex *mu) EXCLUSIVE_LOCK_FUNCTION(mu)
      : mu_(mu) {
    mu->WriterLock();
  }

  WriterMutexLock(const WriterMutexLock&) = delete;
  WriterMutexLock(WriterMutexLock&&) = default;
  WriterMutexLock& operator=(const WriterMutexLock&) = delete;
  WriterMutexLock& operator=(WriterMutexLock&&) = default;

  ~WriterMutexLock() UNLOCK_FUNCTION() {
    this->mu_->WriterUnlock();
  }

 private:
  absl::Mutex *const mu_;
};

#endif

// wraps the p4info pointer provided by the PI library into a unique_ptr
auto p4info_deleter = [](pi_p4info_t *p4info) {
  pi_destroy_config(p4info);
};
using P4InfoWrapper = std::unique_ptr<pi_p4info_t, decltype(p4info_deleter)>;

class P4ErrorReporter {
 public:
  void push_back(const p4v1::Error &error) {
    if (error.canonical_code() != Code::OK)
      errors.emplace_back(index, error);
    index++;
  }

  // TODO(antonin): remove this overload when we generalize the use of
  // p4v1::Error in the code?
  void push_back(const Status &status) {
    if (status.code() != Code::OK) {
      p4v1::Error error;
      error.set_canonical_code(status.code());
      error.set_message(status.message());
      error.set_space("ALL-sswitch-p4org");
      errors.emplace_back(index, error);
    }
    index++;
  }

  Status get_status() const {
    Status status;
    if (errors.empty()) {
      status.set_code(Code::OK);
    } else {
      p4v1::Error success;
      success.set_code(Code::OK);
      status.set_code(Code::UNKNOWN);
      size_t i = 0;
      for (const auto &p : errors) {
        for (; i++ < p.first;) {
          auto success_any = status.add_details();
          success_any->PackFrom(success);
        }
        auto error_any = status.add_details();
        error_any->PackFrom(p.second);
      }
      // add trailing OKs
      for (; i++ < index;) {
        auto success_any = status.add_details();
        success_any->PackFrom(success);
      }
    }
    return status;
  }

 private:
  std::vector<std::pair<size_t, p4v1::Error> > errors{};
  size_t index{0};
};

struct OneShotCleanup : public common::LocalCleanupIface {
  OneShotCleanup(ActionProfMgr *action_prof_mgr,
                 pi_indirect_handle_t group_h)
      : action_prof_mgr(action_prof_mgr), group_h_to_delete(group_h) { }

  Status cleanup(const SessionTemp &session) override {
    if (!action_prof_mgr) RETURN_OK_STATUS();
    auto status =
        action_prof_mgr->oneshot_group_delete(group_h_to_delete, session);
    if (IS_ERROR(status)) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error encountered when cleaning up action profile group created "
          "by one-shot indirect table programming. This is a serious error and "
          "there is now a dangling action profile group. You may need to "
          "reboot the system");
    }
    RETURN_OK_STATUS();
  }

  void cancel() override {
    action_prof_mgr = nullptr;
  }

  void update_group_h(pi_indirect_handle_t group_h) {
    group_h_to_delete = group_h;
  }

  ActionProfMgr *action_prof_mgr;
  pi_indirect_handle_t group_h_to_delete;
};

// Saves the p4_device_config (target-specific) to a temporary file for later
// retrieval by GetForwardingPipelineConfig
struct ConfigFile {
 public:
  ConfigFile() { }

  ~ConfigFile() {
    if (fp != nullptr) std::fclose(fp);
  }

  Status change_config(const p4v1::ForwardingPipelineConfig &config_proto) {
    if (fp != nullptr) std::fclose(fp);  // delete old file
    fp = std::tmpfile();  // new temporary file
    if (!fp) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL, "Cannot create temporary file to save config");
    }
    if (config_proto.p4_device_config().size() > 0) {
      auto nb_written = std::fwrite(config_proto.p4_device_config().data(),
                                    config_proto.p4_device_config().size(),
                                    1,
                                    fp);
      if (nb_written != 1) {
        RETURN_ERROR_STATUS(
            Code::INTERNAL, "Error when saving config to temporary file");
      }
    }
    size = config_proto.p4_device_config().size();
    RETURN_OK_STATUS();
  }

  Status read_config(p4v1::ForwardingPipelineConfig *config_proto) {
    if (!fp || size == 0) RETURN_OK_STATUS();  // no config was saved
    if (std::fseek(fp, 0, SEEK_SET) != 0) {  // seek to start
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error when reading saved config from temporary file");
    }
    // Unfortunately, in C++11, one cannot write directly to the std::string
    // storage (unlike in C++17), so we need an extra copy. To avoid having 2
    // copies of the config simultaneously in memory, we read the file by chunks
    // of 512 bytes.
    char buffer[512];
    auto *device_config = config_proto->mutable_p4_device_config();
    device_config->reserve(size);
    size_t iters = size / sizeof(buffer);
    size_t remainder = size - iters * sizeof(buffer);
    size_t i;
    for (i = 0; i < iters && std::fread(buffer, sizeof(buffer), 1, fp); i++) {
      device_config->append(buffer, sizeof(buffer));
    }
    if (i != iters ||
        (remainder != 0 && !std::fread(buffer, remainder, 1, fp))) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error when reading saved config from temporary file");
    }
    device_config->append(buffer, remainder);
    RETURN_OK_STATUS();
  }

 private:
  std::FILE *fp{nullptr};
  size_t size{0};
};

}  // namespace

class DeviceMgrImp {
 public:
  explicit DeviceMgrImp(device_id_t device_id)
      : device_id(device_id),
        device_tgt({static_cast<pi_dev_id_t>(device_id), 0xffff}),
        packet_io(device_id),
        digest_mgr(device_id),
        idle_timeout_buffer(device_id, &table_info_store) { }

  ~DeviceMgrImp() {
    pi_remove_device(device_id);
  }

  DeviceMgrImp(const DeviceMgrImp &) = delete;
  DeviceMgrImp &operator=(const DeviceMgrImp &) = delete;
  DeviceMgrImp(DeviceMgrImp &&) = delete;
  DeviceMgrImp &operator=(DeviceMgrImp &&) = delete;

  Status p4_change(const p4v1::ForwardingPipelineConfig &config_proto_new,
                   pi_p4info_t *p4info_new) {
    const auto &p4info_proto_new = config_proto_new.p4info();

    // needs to happen before we start modifying the table store
    // the p4_change call will block until all pending notifications have been
    // processed; at this stage we assume no more notifications are received
    // from the target (since the pi_update_device_start call has returned)
    // until the pi_update_device_end call is made.
    idle_timeout_buffer.p4_change(p4info_new);

    SessionTemp session(false  /* = batch */);

    table_info_store.reset();
    for (auto t_id = pi_p4info_table_begin(p4info_new);
         t_id != pi_p4info_table_end(p4info_new);
         t_id = pi_p4info_table_next(p4info_new, t_id)) {
      table_info_store.add_table(t_id);
      // Add the default entry to the table store. In P4_16 a table always has a
      // default entry and this code tries to treat default entries and regular
      // match entries as uniformly as possible. For example when the default
      // entry is set by the client for the first time using MODIFY, there
      // should already be an entry in the store.
      // We assume that the underlying target knows the default entry for each
      // table based on the target-specific blob sent to
      // _pi_update_device_start.
      pi::MatchKey match_key(p4info_new, t_id);
      match_key.set_is_default(true);
      // TODO(antonin): using handle 0 unconditionally for the default entry is
      // not correct and would not work for things like reading / writing direct
      // resources unless the target actually used an internal handle of 0 for
      // default entries. There are some serious PI limitations regarding
      // default entries, in particular for direct resources management, and we
      // need to fix that first before we can properly handle direct resources
      // for default entries in this P4Runtime implementation... For now we
      // return an UNIMPLEMENTED error if the client tries to read / write
      // direct resources for a default entry outside of the context of the
      // TableEntry message. We also do not support reading the default entry
      // yet.
      table_info_store.add_entry(
          t_id, match_key,
          TableInfoStore::Data(0  /* handle */,
                               0  /* controller_metadata */,
                               0  /* idle_timeout_ns */));

      // if idle timeout is supported, set min TTL
      if (pi_p4info_table_supports_idle_timeout(p4info_new, t_id)) {
        // we assume this is a reasonnable value for targets; concretely this
        // means that we don't expect the PI target to be able to support TTLs
        // under 500ms.
        constexpr uint64_t kIdleTimeoutMinTtlNs = 500 * 1000 * 1000;  // 500ms
        pi_idle_timeout_config_t config = {kIdleTimeoutMinTtlNs};
        auto pi_status = pi_table_idle_timeout_config_set(
            session.get(), device_id, t_id, &config);
        if (pi_status != PI_STATUS_SUCCESS) {
          // TODO(antonin): return error code?
          Logger::get()->error("Failed to configure idle timeout on target");
        }
      }
    }

    action_profs.clear();
    // TODO(antonin): use something like Google's ASSIGN_OR_RETURN
    auto pi_api_choice = ActionProfMgr::choose_pi_api(device_id);
    RETURN_IF_ERROR(pi_api_choice.status());
    for (auto act_prof_id = pi_p4info_act_prof_begin(p4info_new);
         act_prof_id != pi_p4info_act_prof_end(p4info_new);
         act_prof_id = pi_p4info_act_prof_next(p4info_new, act_prof_id)) {
      std::unique_ptr<ActionProfMgr> mgr(new ActionProfMgr(
          device_tgt, act_prof_id, p4info_new, pi_api_choice.ValueOrDie()));
      action_profs.emplace(act_prof_id, std::move(mgr));
    }

    auto *pre_mc_mgr_ = new PreMcMgr(device_id);
    pre_clone_mgr.reset(new PreCloneMgr(device_tgt, pre_mc_mgr_));
    pre_mc_mgr.reset(pre_mc_mgr_);

    packet_io.p4_change(p4info_proto_new);

    digest_mgr.p4_change(p4info_proto_new);

    // we do this last, so that the ActProfMgr instances never point to an
    // invalid p4info, even though this is not strictly required here
    p4info.reset(p4info_new);
    p4info_proto.CopyFrom(p4info_proto_new);
    config_cookie.CopyFrom(config_proto_new.cookie());
    RETURN_IF_ERROR(saved_device_config.change_config(config_proto_new));
    is_config_set = true;
    if (config_proto_new.has_cookie()) {
      config_cookie.CopyFrom(config_proto_new.cookie());
      has_config_cookie = true;
    } else {
      has_config_cookie = false;
    }
    RETURN_OK_STATUS();
  }

  Status pipeline_config_set(
      p4v1::SetForwardingPipelineConfigRequest::Action action,
      const p4v1::ForwardingPipelineConfig &config) {
    using SetConfigRequest = p4v1::SetForwardingPipelineConfigRequest;
    pi_status_t pi_status;
    if (action == SetConfigRequest::UNSPECIFIED) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Invalid SetForwardingPipeline action");
    }

    pi_p4info_t *p4info_tmp = nullptr;
    if (action == SetConfigRequest::VERIFY ||
        action == SetConfigRequest::VERIFY_AND_SAVE ||
        action == SetConfigRequest::VERIFY_AND_COMMIT ||
        action == SetConfigRequest::RECONCILE_AND_COMMIT) {
      if (!pi::p4info::p4info_proto_reader(config.p4info(), &p4info_tmp))
        RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when importing p4info");
    }

    if (action == SetConfigRequest::VERIFY)
      RETURN_OK_STATUS();

    p4::tmp::P4DeviceConfig p4_device_config;
    const std::string *device_data = nullptr;
    bool uses_legacy_p4_device_config = false;
    if (p4_device_config.ParseFromString(config.p4_device_config())) {
      device_data = &p4_device_config.device_data();
      uses_legacy_p4_device_config = true;
      Logger::get()->warn("p4::tmp::P4DeviceConfig is deprecated");
    } else {
      device_data = &config.p4_device_config();
    }

    auto lock = unique_lock();

    // check that p4info => device assigned
    assert(!p4info || pi_is_device_assigned(device_id));

    auto remove_device = [this]() {
      pi_remove_device(device_id);
      table_info_store.reset();
      action_profs.clear();
      p4info.reset(nullptr);
    };

    auto make_assign_options = [&p4_device_config]() {
      std::vector<pi_assign_extra_t> assign_options;
      for (const auto &p : p4_device_config.extras().kv()) {
        pi_assign_extra_t e;
        e.key = p.first.c_str();
        e.v = p.second.c_str();
        e.end_of_extras = 0;
        assign_options.push_back(e);
      }
      assign_options.push_back({1, NULL, NULL});
      return assign_options;
    };

    // This is for legacy support of bmv2
    if (action == SetConfigRequest::VERIFY_AND_COMMIT &&
        uses_legacy_p4_device_config &&
        device_data->empty()) {
      if (pi_is_device_assigned(device_id)) remove_device();
      assert(!pi_is_device_assigned(device_id));
      auto assign_options = make_assign_options();
      pi_status = pi_assign_device(device_id, p4info_tmp,
                                   assign_options.data());
      if (pi_status != PI_STATUS_SUCCESS) {
        pi_destroy_config(p4info_tmp);
        RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when assigning device");
      }
      RETURN_IF_ERROR(p4_change(config, p4info_tmp));
      RETURN_OK_STATUS();
    }

    // assign device if needed, i.e. if device hasn't been assigned yet or if
    // the reassign flag is set
    if (action == SetConfigRequest::VERIFY_AND_SAVE ||
        action == SetConfigRequest::VERIFY_AND_COMMIT ||
        action == SetConfigRequest::RECONCILE_AND_COMMIT) {
      if (uses_legacy_p4_device_config &&
          pi_is_device_assigned(device_id) &&
          p4_device_config.reassign()) {
        remove_device();
      }
      if (!pi_is_device_assigned(device_id)) {
        auto assign_options = make_assign_options();
        pi_status = pi_assign_device(device_id, NULL, assign_options.data());
        if (pi_status != PI_STATUS_SUCCESS) {
          pi_destroy_config(p4info_tmp);
          RETURN_ERROR_STATUS(Code::UNKNOWN,
                              "Error when trying to assign device");
        }
      }
    }

    // for reconcile, as per the P4Runtime spec, we need to preserve the
    // forwarding state if possible, which is why we do a read to store all
    // existing state.
    p4v1::ReadResponse forwarding_state;
    if (action == SetConfigRequest::RECONCILE_AND_COMMIT) {
      auto status = save_forwarding_state(&forwarding_state);
      if (IS_ERROR(status)) {
        pi_destroy_config(p4info_tmp);
        return status;
      }
    }

    if (action == SetConfigRequest::VERIFY_AND_SAVE ||
        action == SetConfigRequest::VERIFY_AND_COMMIT ||
        action == SetConfigRequest::RECONCILE_AND_COMMIT) {
      pi_status = pi_update_device_start(device_id, p4info_tmp,
                                         device_data->data(),
                                         device_data->size());
      if (pi_status != PI_STATUS_SUCCESS) {
        pi_destroy_config(p4info_tmp);
        RETURN_ERROR_STATUS(Code::UNKNOWN,
                            "Error in first phase of device update");
      }
      RETURN_IF_ERROR(p4_change(config, p4info_tmp));
    }

    // for reconcile, replay the state saved before the pi_update_device_start
    // call (which itself wipes the state)
    if (action == SetConfigRequest::RECONCILE_AND_COMMIT) {
      p4v1::WriteRequest write_request;
      for (auto &entity : *forwarding_state.mutable_entities()) {
        auto *update = write_request.add_updates();
        update->set_type(p4v1::Update::INSERT);
        update->set_allocated_entity(&entity);
      }
      auto status = write_(write_request);
      for (auto &update : *write_request.mutable_updates())
        update.release_entity();
      if (IS_ERROR(status))
        RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when reconciling config")
    }

    if (action == SetConfigRequest::VERIFY_AND_COMMIT ||
        action == SetConfigRequest::COMMIT ||
        action == SetConfigRequest::RECONCILE_AND_COMMIT) {
      pi_status = pi_update_device_end(device_id);
      if (pi_status != PI_STATUS_SUCCESS) {
        RETURN_ERROR_STATUS(Code::UNKNOWN,
                            "Error in second phase of device update");
      }
    }

    RETURN_OK_STATUS();
  }

  Status pipeline_config_get(
      p4v1::GetForwardingPipelineConfigRequest::ResponseType response_type,
      p4v1::ForwardingPipelineConfig *config) {
    // if no config has been set, return an "empty" message
    if (!is_config_set) RETURN_OK_STATUS();
    using GetConfigRequest = p4v1::GetForwardingPipelineConfigRequest;
    switch (response_type) {
      case GetConfigRequest::ALL:
        config->mutable_p4info()->CopyFrom(p4info_proto);
        RETURN_IF_ERROR(saved_device_config.read_config(config));
        break;
      case GetConfigRequest::COOKIE_ONLY:
        break;
      case GetConfigRequest::P4INFO_AND_COOKIE:
        config->mutable_p4info()->CopyFrom(p4info_proto);
        break;
      case GetConfigRequest::DEVICE_CONFIG_AND_COOKIE:
        RETURN_IF_ERROR(saved_device_config.read_config(config));
        break;
      default:
        RETURN_ERROR_STATUS(
            Code::INVALID_ARGUMENT,
            "Invalid response_type in GetForwardingPipelineConfigRequest");
    }
    // always add cookie
    if (has_config_cookie)
      config->mutable_cookie()->CopyFrom(config_cookie);
    RETURN_OK_STATUS();
  }

  Status write(const p4v1::WriteRequest &request) {
    auto lock = shared_lock();
    return write_(request);
  }

  Status read(const p4v1::ReadRequest &request,
              p4v1::ReadResponse *response) const {
    auto lock = unique_lock();
    return read_(request, response);
  }

  Status read_one(const p4v1::Entity &entity,
                  p4v1::ReadResponse *response) const {
    auto lock = unique_lock();
    return read_one_(entity, response);
  }

  Status table_write(p4v1::Update::Type update,
                     const p4v1::TableEntry &table_entry,
                     SessionTemp *session) {
    if (!check_p4_id(table_entry.table_id(), P4Ids::TABLE))
      return make_invalid_p4_id_status();

    if (table_entry.has_time_since_last_hit()) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "has_time_since_last_hit must not be set in WriteRequest");
    }

    switch (update) {
      case p4v1::Update::UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Update type is not set");
      case p4v1::Update::INSERT:
        return table_insert(table_entry, session);
      case p4v1::Update::MODIFY:
        return table_modify(table_entry, session);
      case p4v1::Update::DELETE:
        return table_delete(table_entry, session);
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid update type");
        break;
    }
    RETURN_OK_STATUS();  // unreachable
  }

  Status meter_write(p4v1::Update::Type update,
                     const p4v1::MeterEntry &meter_entry,
                     const SessionTemp &session) {
    if (!check_p4_id(meter_entry.meter_id(), P4Ids::METER))
      return make_invalid_p4_id_status();
    if (!meter_entry.has_index()) {
      RETURN_ERROR_STATUS(
          Code::UNIMPLEMENTED,
          "Wildcard write is not supported for indirect meters yet");
    }
    if (meter_entry.index().index() < 0) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "A negative number is not a valid index value");
    }
    auto index = static_cast<size_t>(meter_entry.index().index());
    switch (update) {
      case p4v1::Update::UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Update type is not set");
      case p4v1::Update::INSERT:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "INSERT update type not supported for meters");
      case p4v1::Update::MODIFY:
        {
          auto status = validate_meter_spec(meter_entry.config());
          if (IS_ERROR(status)) return status;
          auto pi_meter_spec = meter_spec_proto_to_pi(
              meter_entry.config(), meter_entry.meter_id());
          auto pi_status = pi_meter_set(session.get(), device_tgt,
                                        meter_entry.meter_id(),
                                        index,
                                        &pi_meter_spec);
          if (pi_status != PI_STATUS_SUCCESS)
            RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when writing meter spec");
        }
        break;
      case p4v1::Update::DELETE:  // TODO(antonin): return error instead?
        {
          pi_meter_spec_t pi_meter_spec =
              {0, 0, 0, 0, PI_METER_UNIT_DEFAULT, PI_METER_TYPE_DEFAULT};
          auto pi_status = pi_meter_set(session.get(), device_tgt,
                                        meter_entry.meter_id(),
                                        index,
                                        &pi_meter_spec);
          if (pi_status != PI_STATUS_SUCCESS)
            RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when writing meter spec");
        }
        break;
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid update type");
    }
    RETURN_OK_STATUS();
  }

  Status entry_handle_from_table_entry(const p4v1::TableEntry &table_entry,
                                       pi_entry_handle_t *handle) const {
    pi::MatchKey match_key(p4info.get(), table_entry.table_id());
    {
      auto status = construct_match_key(table_entry, &match_key);
      if (IS_ERROR(status)) return status;
    }
    auto entry_data = table_info_store.get_entry(
        table_entry.table_id(), match_key);
    if (entry_data == nullptr) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Cannot map table entry to handle");
    }
    *handle = entry_data->handle;
    RETURN_OK_STATUS();
  }

  Status direct_meter_write(p4v1::Update::Type update,
                            const p4v1::DirectMeterEntry &meter_entry,
                            const SessionTemp &session) {
    if (!meter_entry.has_table_entry()) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Missing table_entry field in DirectMeterEntry");
    }
    const auto &table_entry = meter_entry.table_entry();
    if (!check_p4_id(table_entry.table_id(), P4Ids::TABLE))
      return make_invalid_p4_id_status();
    if (table_entry.is_default_action()) {
      RETURN_ERROR_STATUS(
          Code::UNIMPLEMENTED,
          "Writing DirectMeterEntry not supported for default entry yet");
    }
    auto table_lock = table_info_store.lock_table(table_entry.table_id());

    pi_entry_handle_t entry_handle = 0;
    {
      auto status = entry_handle_from_table_entry(table_entry, &entry_handle);
      if (IS_ERROR(status)) return status;
    }

    p4_id_t table_direct_meter_id = pi_get_table_direct_resource_p4_id(
        table_entry.table_id(), P4Ids::DIRECT_METER);
    if (table_direct_meter_id == PI_INVALID_ID) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Table has no direct meters");
    }
    switch (update) {
      case p4v1::Update::UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Update type is not set");
      case p4v1::Update::INSERT:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "INSERT update type not supported for meters");
      case p4v1::Update::MODIFY:
        {
          auto status = validate_meter_spec(meter_entry.config());
          if (IS_ERROR(status)) return status;
          auto pi_meter_spec = meter_spec_proto_to_pi(
              meter_entry.config(), table_direct_meter_id);
          auto pi_status = pi_meter_set_direct(session.get(), device_tgt,
                                               table_direct_meter_id,
                                               entry_handle,
                                               &pi_meter_spec);
          if (pi_status != PI_STATUS_SUCCESS) {
            RETURN_ERROR_STATUS(Code::UNKNOWN,
                                "Error when writing direct meter spec");
          }
        }
        break;
      case p4v1::Update::DELETE:  // TODO(antonin): return error instead?
        {
          pi_meter_spec_t pi_meter_spec =
              {0, 0, 0, 0, PI_METER_UNIT_DEFAULT, PI_METER_TYPE_DEFAULT};
          auto pi_status = pi_meter_set_direct(session.get(), device_tgt,
                                               table_direct_meter_id,
                                               entry_handle,
                                               &pi_meter_spec);
          if (pi_status != PI_STATUS_SUCCESS) {
            RETURN_ERROR_STATUS(Code::UNKNOWN,
                                "Error when writing direct meter spec");
          }
        }
        break;
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid update type");
    }
    RETURN_OK_STATUS();
  }

  Status meter_read_one(p4_id_t meter_id,
                        const p4v1::MeterEntry &meter_entry,
                        const SessionTemp &session,
                        p4v1::ReadResponse *response) const {
    assert(pi_p4info_meter_get_direct(p4info.get(), meter_id) ==
           PI_INVALID_ID);
    if (meter_entry.has_index()) {
      if (meter_entry.index().index() < 0) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "A negative number is not a valid index value");
      }
      auto entry = response->add_entities()->mutable_meter_entry();
      entry->CopyFrom(meter_entry);
      return meter_read_one_index(session, meter_id, entry);
    }
    // default index, read all
    auto meter_size = pi_p4info_meter_get_size(p4info.get(), meter_id);
    for (size_t index = 0; index < meter_size; index++) {
      auto entry = response->add_entities()->mutable_meter_entry();
      entry->set_meter_id(meter_id);
      auto index_msg = entry->mutable_index();
      index_msg->set_index(index);
      auto status = meter_read_one_index(session, meter_id, entry);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status meter_read(const p4v1::MeterEntry &meter_entry,
                    const SessionTemp &session,
                    p4v1::ReadResponse *response) const {
    auto meter_id = meter_entry.meter_id();
    if (meter_id == 0) {  // read all entries for all meters
      for (auto m_id = pi_p4info_meter_begin(p4info.get());
           m_id != pi_p4info_meter_end(p4info.get());
           m_id = pi_p4info_meter_next(p4info.get(), m_id)) {
        if (pi_p4info_meter_get_direct(p4info.get(), m_id) != PI_INVALID_ID)
          continue;
        auto status = meter_read_one(m_id, meter_entry, session, response);
        if (IS_ERROR(status)) return status;
      }
    } else {  // read for a single meter
      if (!check_p4_id(meter_id, P4Ids::METER))
        return make_invalid_p4_id_status();
      if (pi_p4info_meter_get_direct(p4info.get(), meter_id) != PI_INVALID_ID) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Cannot use MeterEntry with a direct meter");
      }
      auto status = meter_read_one(meter_id, meter_entry, session, response);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status direct_meter_read_one(const p4v1::TableEntry &table_entry,
                               const SessionTemp &session,
                               p4v1::ReadResponse *response) const {
    if (!table_entry.match().empty()) {
      auto table_lock = table_info_store.lock_table(table_entry.table_id());

      pi_entry_handle_t entry_handle = 0;
      {
        auto status = entry_handle_from_table_entry(table_entry, &entry_handle);
        if (IS_ERROR(status)) return status;
      }
      p4_id_t table_direct_meter_id = pi_get_table_direct_resource_p4_id(
        table_entry.table_id(), P4Ids::DIRECT_METER);
      if (table_direct_meter_id == PI_INVALID_ID) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Table has no direct meters");
      }
      pi_meter_spec_t meter_spec;
      auto pi_status = pi_meter_read_direct(
          session.get(), device_tgt, table_direct_meter_id, entry_handle,
          &meter_spec);
      if (pi_status != PI_STATUS_SUCCESS) {
        RETURN_ERROR_STATUS(Code::UNKNOWN,
                            "Error when reading meter from target");
      }
      auto entry = response->add_entities()->mutable_direct_meter_entry();
      entry->mutable_table_entry()->CopyFrom(table_entry);
      meter_spec_pi_to_proto(meter_spec, entry->mutable_config());
      RETURN_OK_STATUS();
    }
    // read all direct meters in table
    RETURN_ERROR_STATUS(
        Code::UNIMPLEMENTED,
        "Reading ALL direct meters in a table is not supported yet");
  }

  Status direct_meter_read(const p4v1::DirectMeterEntry &meter_entry,
                           const SessionTemp &session,
                           p4v1::ReadResponse *response) const {
    if (!meter_entry.has_table_entry()) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Missing table_entry field in DirectMeterEntry");
    }
    const auto &table_entry = meter_entry.table_entry();
    if (table_entry.table_id() == 0) {
      RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
        "Reading ALL direct meters for all tables is not supported yet");
    }
    if (!check_p4_id(table_entry.table_id(), P4Ids::TABLE))
      return make_invalid_p4_id_status();
    if (table_entry.is_default_action()) {
      RETURN_ERROR_STATUS(
          Code::UNIMPLEMENTED,
          "Reading DirectMeterEntry not supported for default entry yet");
    }
    return direct_meter_read_one(table_entry, session, response);
  }

  Status parse_action_data(const pi_action_data_t *pi_action_data,
                           p4v1::Action *action) const {
    ActionDataReader reader(pi_action_data);
    auto action_id = reader.get_action_id();
    action->set_action_id(action_id);
    size_t num_params;
    auto param_ids = pi_p4info_action_get_params(
        p4info.get(), action_id, &num_params);
    for (size_t j = 0; j < num_params; j++) {
      auto param = action->add_params();
      param->set_param_id(param_ids[j]);
      reader.get_arg(param_ids[j], param->mutable_value());
    }
    RETURN_OK_STATUS();
  }

  Status parse_action_entry(
      p4_id_t table_id,
      const pi_table_entry_t *pi_entry,
      p4v1::TableEntry *entry,
      const std::unordered_map<
        pi_indirect_handle_t,
        p4v1::ActionProfileActionSet> &oneshot_map) const {
    if (pi_entry->entry_type == PI_ACTION_ENTRY_TYPE_NONE) RETURN_OK_STATUS();

    auto table_action = entry->mutable_action();
    if (pi_entry->entry_type == PI_ACTION_ENTRY_TYPE_INDIRECT) {
      auto indirect_h = pi_entry->entry.indirect_handle;
      auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                               table_id);
      // check that table is indirect
      if (action_prof_id == PI_INVALID_ID) {
        RETURN_ERROR_STATUS(Code::INTERNAL,
                            "No implementation found for indirect table");
      }
      auto action_prof_mgr = get_action_prof_mgr(action_prof_id);
      switch (action_prof_mgr->get_selector_usage()) {
        case ActionProfMgr::SelectorUsage::UNSPECIFIED:
          RETURN_ERROR_STATUS(Code::INTERNAL, "Invalid selector mode");
        case ActionProfMgr::SelectorUsage::ONESHOT:
          {
            auto p_it = oneshot_map.find(indirect_h);
            if (p_it == oneshot_map.end())
              RETURN_ERROR_STATUS(Code::INTERNAL, "Invalid group handle");
            table_action->mutable_action_profile_action_set()->CopyFrom(
                p_it->second);
            RETURN_OK_STATUS();
          }
        case ActionProfMgr::SelectorUsage::MANUAL:
          {
            ActionProfMgr::Id member_id;
            if (action_prof_mgr->retrieve_member_id(indirect_h, &member_id)) {
              table_action->set_action_profile_member_id(member_id);
              RETURN_OK_STATUS();
            }
            ActionProfMgr::Id group_id;
            if (!action_prof_mgr->retrieve_group_id(indirect_h, &group_id))
              RETURN_ERROR_STATUS(Code::INTERNAL, "Invalid indirect handle");
            table_action->set_action_profile_group_id(group_id);
            RETURN_OK_STATUS();
          }
      }
    }

    return parse_action_data(pi_entry->entry.action_data,
                             table_action->mutable_action());
  }

  // Map group handles to an ActionProfileActionSet message. This is required
  // for read-write symmetry when reading the contents of an action selector
  // programmed with the one-shot method. If the table is not indirect or the
  // selector does not use one-shot, nothing is added to the map.
  Status build_action_profile_action_set_map(
      p4_id_t table_id,
      std::unordered_map<pi_indirect_handle_t,
                         p4v1::ActionProfileActionSet> *map,
      const SessionTemp &session) const {
    auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                             table_id);
    // check that table is indirect
    if (action_prof_id == PI_INVALID_ID) RETURN_OK_STATUS();
    auto action_prof_mgr = get_action_prof_mgr(action_prof_id);
    assert(action_prof_mgr);

    if (action_prof_mgr->get_selector_usage() !=
        ActionProfMgr::SelectorUsage::ONESHOT) {
      RETURN_OK_STATUS();
    }

    pi_act_prof_fetch_res_t *res;
    auto pi_status = pi_act_prof_entries_fetch(session.get(), device_id,
                                               action_prof_id, &res);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::UNKNOWN,
          "Error when fetching action profile entries from target");
    }

    // first, build a map from member handle to action specification
    std::unordered_map<pi_indirect_handle_t, p4v1::Action> mbr_h_to_action;
    auto num_members = pi_act_prof_mbrs_num(res);
    for (size_t i = 0; i < num_members; i++) {
      pi_action_data_t *action_data;
      pi_indirect_handle_t member_h;
      pi_act_prof_mbrs_next(res, &action_data, &member_h);
      auto p = mbr_h_to_action.emplace(member_h, p4v1::Action());
      if (!p.second)
        RETURN_ERROR_STATUS(Code::INTERNAL, "Duplicate member handle");
      RETURN_IF_ERROR(parse_action_data(action_data, &p.first->second));
    }

    // then, iterate over groups and build the corresponding
    // ActionProfileActionSet using the action specifications included in
    // mbr_h_to_action,
    auto num_groups = pi_act_prof_grps_num(res);
    for (size_t i = 0; i < num_groups; i++) {
      pi_indirect_handle_t *members_h;
      size_t num;
      pi_indirect_handle_t group_h;
      pi_act_prof_grps_next(res, &members_h, &num, &group_h);
      auto p = map->emplace(group_h, p4v1::ActionProfileActionSet());
      if (!p.second)
        RETURN_ERROR_STATUS(Code::INTERNAL, "Duplicate group handle");
      // we cannot rely on the target returning the members in the correct order
      // (read-write symmetry), so we use the member list stored in
      // ActionProfMgr.
      std::vector<ActionProfMgr::OneShotMember> members_in_order;
      if (!action_prof_mgr->oneshot_group_get_members(
              group_h, &members_in_order)) {
        RETURN_ERROR_STATUS(Code::INTERNAL, "Unknown group handle");
      }
      if (num != members_in_order.size())
        RETURN_ERROR_STATUS(Code::INTERNAL, "Mismatch in group size");
      auto *ap_action_set = &p.first->second;
      for (size_t j = 0; j < num; j++) {
        const auto &member = members_in_order[j];
        if (member.weight == 0) continue;
        auto *ap_action = ap_action_set->add_action_profile_actions();
        auto action_spec_it = mbr_h_to_action.find(member.member_h);
        if (action_spec_it == mbr_h_to_action.end())
          RETURN_ERROR_STATUS(Code::INTERNAL, "Invalid member handle in group");
        ap_action->mutable_action()->CopyFrom(action_spec_it->second);
        ap_action->set_weight(member.weight);
        // TODO(antonin): support watch
      }
    }

    pi_act_prof_entries_fetch_done(session.get(), res);

    RETURN_OK_STATUS();
  }

  // Query the remaining TTL value from the target and deduce the
  // "time_since_last_hit". This should be called when processing a ReadRequest
  // for a TableEntry where the "time_since_last_hit" message field is set, and
  // only if the P4 table actually supports entry ageing.
  Status set_time_since_last_hit(p4_id_t table_id,
                                 pi_entry_handle_t entry_handle,
                                 p4v1::TableEntry *table_entry,
                                 int64_t idle_timeout_ns,
                                 const SessionTemp &session) const {
    auto *time_since_last_hit = table_entry->mutable_time_since_last_hit();
    if (idle_timeout_ns == 0) {
      // TODO(antonin): This violates the spec, which states that we should
      // populate the correct value even for entries for which ageing is
      // disabled, but PI currently doesn't provide us with this information.
      time_since_last_hit->set_elapsed_ns(0);
    } else {
      uint64_t remaining_ttl_ns = 0;
      auto pi_status = pi_table_entry_get_remaining_ttl(
          session.get(), device_id, table_id, entry_handle, &remaining_ttl_ns);
      if (pi_status != PI_STATUS_SUCCESS) {
        RETURN_ERROR_STATUS(
            Code::UNKNOWN,
            "Error when reading remaining entry TTL from target");
      }
      auto remaining_ttl_ns_ = static_cast<int64_t>(remaining_ttl_ns);
      time_since_last_hit->set_elapsed_ns(
          (idle_timeout_ns >= remaining_ttl_ns_) ?
          (idle_timeout_ns - remaining_ttl_ns_) : 0);
    }
    RETURN_OK_STATUS();
  }

  Status table_read_one(p4_id_t table_id,
                        const p4v1::TableEntry &requested_entry,
                        const SessionTemp &session,
                        p4v1::ReadResponse *response) const {
    pi::MatchKey expected_match_key(p4info.get(), table_id);
    if (requested_entry.is_default_action()) {
      RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
                          "Reading default entry not supported yet");
    }
    if (!requested_entry.match().empty()) {
      RETURN_IF_ERROR(
          construct_match_key(requested_entry, &expected_match_key));
    }

    std::unordered_map<pi_indirect_handle_t,
                       p4v1::ActionProfileActionSet> oneshot_map;
    // the map is needed if the table is indirect and was programmed using the
    // oneshot programming method, to guarantee read-write symmetry
    RETURN_IF_ERROR(build_action_profile_action_set_map(
        table_id, &oneshot_map, session));

    bool table_supports_idle_timeout = pi_p4info_table_supports_idle_timeout(
        p4info.get(), table_id);
    if (requested_entry.has_time_since_last_hit() &&
        !table_supports_idle_timeout) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Do not set time_since_last_hit for a ReadRequest if the table "
          "does not support idle timeout; yes, that includes wildcard reads");
    }

    pi_table_fetch_res_t *res;
    auto table_lock = table_info_store.lock_table(table_id);
    auto pi_status = pi_table_entries_fetch(session.get(), device_id,
                                            table_id, &res);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when fetching entries from target");
    }
    auto num_entries = pi_table_entries_num(res);
    pi_table_ma_entry_t entry;
    pi_entry_handle_t entry_handle;
    pi::MatchKey mk(p4info.get(), table_id);
    for (size_t i = 0; i < num_entries; i++) {
      pi_table_entries_next(res, &entry, &entry_handle);

      // Very Very naive solution to filter on a specific match key: we iterate
      // over ALL entries and compare the match key for each one.
      // We require equality for every field, even priority, so this is reqlly
      // just meant to be used as a very inefficient way to retrieve a single
      // table entry...

      // TODO(antonin): what I really want to do here is a heterogeneous lookup
      // / comparison; instead I make a copy of the match key in the right
      // format and I use this for the lookup. If this is a performance issue,
      // we can find a better solution.
      mk.from(entry.match_key);
      if (!requested_entry.match().empty() &&
          !pi::MatchKeyEq()(mk, expected_match_key)) {
        continue;
      }

      auto *table_entry = response->add_entities()->mutable_table_entry();
      table_entry->set_table_id(table_id);
      RETURN_IF_ERROR(parse_match_key(p4info.get(), table_id, mk, table_entry));
      RETURN_IF_ERROR(
          parse_action_entry(table_id, &entry.entry, table_entry, oneshot_map));

      // direct resources
      auto *direct_configs = entry.entry.direct_res_config;
      if (direct_configs != nullptr) {
        for (size_t j = 0; j < direct_configs->num_configs; j++) {
          const auto &config = direct_configs->configs[j];
          if (pi_is_direct_counter_id(config.res_id)) {
            if (requested_entry.has_counter_data()) {
              counter_data_pi_to_proto(
                  *static_cast<pi_counter_data_t *>(config.config),
                  table_entry->mutable_counter_data());
            }
          } else if (pi_is_direct_meter_id(config.res_id)) {
            // TODO(antonin): according to the P4Runtime spec, we are not
            // supposed to to set meter_config if the meter is in its default
            // configuration (all packets green).
            if (requested_entry.has_meter_config()) {
              meter_spec_pi_to_proto(
                  *static_cast<pi_meter_spec_t *>(config.config),
                  table_entry->mutable_meter_config());
            }
          } else {
            RETURN_ERROR_STATUS(Code::INTERNAL, "Unknown direct resource type");
          }
        }
      }

      // If table is const (immutable P4 table), it is possible that the entries
      // were added out-of-band, i.e. without the P4Runtime service. In this
      // case, the entries would not be found in the table_info_store, and
      // anyway there would be no point in looking since there can be no
      // controller metadata for these immutable entries.
      bool table_is_const = pi_p4info_table_is_const(p4info.get(), table_id);
      if (table_is_const) continue;
      auto entry_data = table_info_store.get_entry(table_id, mk);
      // this would point to a serious bug in the implementation, and shoudn't
      // occur given that we keep the local state in sync with lower level state
      // thanks to our per-table lock.
      if (entry_data == nullptr) {
        RETURN_ERROR_STATUS(Code::INTERNAL,
                            "Table state out-of-sync with target");
      }
      table_entry->set_controller_metadata(entry_data->controller_metadata);
      table_entry->set_idle_timeout_ns(entry_data->idle_timeout_ns);

      if (requested_entry.has_time_since_last_hit()) {
        RETURN_IF_ERROR(set_time_since_last_hit(
            table_id, entry_handle, table_entry, entry_data->idle_timeout_ns,
            session));
      }

      // just a sanity check
      assert(
          entry_data->is_oneshot ==
          (table_entry->action().type_case() ==
           p4v1::TableAction::kActionProfileActionSet));
    }

    pi_table_entries_fetch_done(session.get(), res);

    RETURN_OK_STATUS();
  }

  // TODO(antonin): full filtering on the match key, action, ... as per the spec
  Status table_read(const p4v1::TableEntry &table_entry,
                    const SessionTemp &session,
                    p4v1::ReadResponse *response) const {
    if (table_entry.table_id() == 0) {  // read all entries for all tables
      for (auto t_id = pi_p4info_table_begin(p4info.get());
           t_id != pi_p4info_table_end(p4info.get());
           t_id = pi_p4info_table_next(p4info.get(), t_id)) {
        auto status = table_read_one(t_id, table_entry, session, response);
        if (IS_ERROR(status)) return status;
      }
    } else {  // read for a single table
      if (!check_p4_id(table_entry.table_id(), P4Ids::TABLE))
        return make_invalid_p4_id_status();
      auto status = table_read_one(
          table_entry.table_id(), table_entry, session, response);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status action_profile_member_write(p4v1::Update::Type update,
                                     const p4v1::ActionProfileMember &member,
                                     const SessionTemp &session) {
    if (!check_p4_id(member.action_profile_id(), P4Ids::ACTION_PROFILE))
      return make_invalid_p4_id_status();
    auto action_prof_mgr = get_action_prof_mgr(member.action_profile_id());
    if (action_prof_mgr == nullptr) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Not a valid action profile id: {}",
                          member.action_profile_id());
    }
    switch (update) {
      case p4v1::Update::UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Update type is not set");
      case p4v1::Update::INSERT:
        return action_prof_mgr->member_create(member, session);
      case p4v1::Update::MODIFY:
        return action_prof_mgr->member_modify(member, session);
      case p4v1::Update::DELETE:
        return action_prof_mgr->member_delete(member, session);
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid update type");
    }
    assert(0);
    RETURN_ERROR_STATUS(Code::INTERNAL);  // UNREACHABLE
  }

  Status action_profile_group_write(p4v1::Update::Type update,
                                    const p4v1::ActionProfileGroup &group,
                                    const SessionTemp &session) {
    if (!check_p4_id(group.action_profile_id(), P4Ids::ACTION_PROFILE))
      return make_invalid_p4_id_status();
    auto action_prof_mgr = get_action_prof_mgr(group.action_profile_id());
    if (action_prof_mgr == nullptr) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Not a valid action profile id: {}",
                          group.action_profile_id());
    }
    switch (update) {
      case p4v1::Update::UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Update type is not set");
      case p4v1::Update::INSERT:
        return action_prof_mgr->group_create(group, session);
      case p4v1::Update::MODIFY:
        return action_prof_mgr->group_modify(group, session);
      case p4v1::Update::DELETE:
        return action_prof_mgr->group_delete(group, session);
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid update type");
    }
    assert(0);
    RETURN_ERROR_STATUS(Code::INTERNAL);  // UNREACHABLE
  }

  template <typename T, typename MemberAccessor, typename GroupAccessor>
  Status action_profile_read_common(
      p4_id_t action_profile_id, const SessionTemp &session,
      T *entries, MemberAccessor MAn, GroupAccessor GAn) const {
    auto action_prof_mgr = get_action_prof_mgr(action_profile_id);
    if (action_prof_mgr == nullptr) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Not a valid action profile id: {}",
                          action_profile_id);
    }

    pi_act_prof_fetch_res_t *res;
    auto pi_status = pi_act_prof_entries_fetch(session.get(), device_id,
                                               action_profile_id, &res);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::UNKNOWN,
          "Error when fetching action profile entries from target");
    }

    Code code = Code::OK;
    auto num_members = pi_act_prof_mbrs_num(res);
    for (size_t i = 0; i < num_members; i++) {
      pi_action_data_t *action_data;
      pi_indirect_handle_t member_h;
      auto member = MAn(entries);
      if (member == nullptr) break;
      member->set_action_profile_id(action_profile_id);
      pi_act_prof_mbrs_next(res, &action_data, &member_h);
      RETURN_IF_ERROR(parse_action_data(action_data, member->mutable_action()));
      ActionProfMgr::Id member_id;
      if (!action_prof_mgr->retrieve_member_id(member_h, &member_id)) {
        RETURN_ERROR_STATUS(Code::INTERNAL,
                            "Cannot map member handle to member id");
      }
      member->set_member_id(member_id);
    }

    auto num_groups = pi_act_prof_grps_num(res);
    for (size_t i = 0; i < num_groups; i++) {
      pi_indirect_handle_t *members_h;
      size_t num;
      pi_indirect_handle_t group_h;
      auto group = GAn(entries);
      if (group == nullptr) break;
      group->set_action_profile_id(action_profile_id);
      pi_act_prof_grps_next(res, &members_h, &num, &group_h);
      ActionProfMgr::Id group_id;
      if (!action_prof_mgr->retrieve_group_id(group_h, &group_id)) {
        RETURN_ERROR_STATUS(Code::INTERNAL,
                            "Cannot map group handle to group id");
      }
      group->set_group_id(group_id);
      size_t max_size;
      if (!action_prof_mgr->group_get_max_size_user(group_id, &max_size)) {
        RETURN_ERROR_STATUS(Code::INTERNAL,
                            "Cannot retrieve max_size for group {}", group_id);
      }
      group->set_max_size(static_cast<int>(max_size));
      // TODO(antonin): while this is probably good to read from PI and validate
      // consistency, it is quite expensive compared to just using the state
      // stored in ActionProfMgr. Maybe we should consider doing that (or maybe
      // have a flag to choose one or the other).
      std::map<ActionProfMgr::Id, int> member_weights;
      for (size_t j = 0; j < num; j++) {
        ActionProfMgr::Id member_id;
        if (!action_prof_mgr->retrieve_member_id(members_h[j], &member_id)) {
          RETURN_ERROR_STATUS(Code::INTERNAL,
                              "Cannot map member handle to member id");
        }
        member_weights[member_id]++;
      }
      for (const auto &m : member_weights) {
        auto member = group->add_members();
        member->set_member_id(m.first);
        member->set_weight(m.second);
        // TODO(antonin): support watch
      }
    }

    pi_act_prof_entries_fetch_done(session.get(), res);

    RETURN_STATUS(code);
  }

  Status action_profile_member_read_one(p4_id_t action_profile_id,
                                        const SessionTemp &session,
                                        p4v1::ReadResponse *response) const {
    return action_profile_read_common(
        action_profile_id, session, response,
        [] (decltype(response) r) {
          return r->add_entities()->mutable_action_profile_member(); },
        [] (decltype(response)) -> p4v1::ActionProfileGroup * {
          return nullptr; });
  }

  // TODO(antonin): full filtering
  Status action_profile_member_read(const p4v1::ActionProfileMember &member,
                                    const SessionTemp &session,
                                    p4v1::ReadResponse *response) const {
    if (member.action_profile_id() == 0) {
      for (auto act_prof_id = pi_p4info_act_prof_begin(p4info.get());
           act_prof_id != pi_p4info_act_prof_end(p4info.get());
           act_prof_id = pi_p4info_act_prof_next(p4info.get(), act_prof_id)) {
        auto status = action_profile_member_read_one(
            act_prof_id, session, response);
        if (IS_ERROR(status)) return status;
      }
    } else {
      if (!check_p4_id(member.action_profile_id(), P4Ids::ACTION_PROFILE))
        return make_invalid_p4_id_status();
      auto status = action_profile_member_read_one(
          member.action_profile_id(), session, response);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status action_profile_group_read_one(p4_id_t action_profile_id,
                                       const SessionTemp &session,
                                       p4v1::ReadResponse *response) const {
    return action_profile_read_common(
        action_profile_id, session, response,
        [] (decltype(response)) -> p4v1::ActionProfileMember * {
          return nullptr; },
        [] (decltype(response) r) {
          return r->add_entities()->mutable_action_profile_group(); });
  }

  // TODO(antonin): full filtering
  Status action_profile_group_read(const p4v1::ActionProfileGroup &group,
                                   const SessionTemp &session,
                                   p4v1::ReadResponse *response) const {
    if (group.action_profile_id() == 0) {
      for (auto act_prof_id = pi_p4info_act_prof_begin(p4info.get());
           act_prof_id != pi_p4info_act_prof_end(p4info.get());
           act_prof_id = pi_p4info_act_prof_next(p4info.get(), act_prof_id)) {
        auto status = action_profile_group_read_one(
            act_prof_id, session, response);
        if (IS_ERROR(status)) return status;
      }
    } else {
      if (!check_p4_id(group.action_profile_id(), P4Ids::ACTION_PROFILE))
        return make_invalid_p4_id_status();
      auto status = action_profile_group_read_one(
          group.action_profile_id(), session, response);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status packet_out_send(const p4v1::PacketOut &packet) const {
    return packet_io.packet_out_send(packet);
  }

  Status stream_message_request_handle(
      const p4::v1::StreamMessageRequest &request) {
    switch (request.update_case()) {
      case p4v1::StreamMessageRequest::kArbitration:
        // must be handled by server code
        RETURN_ERROR_STATUS(
            Code::INTERNAL, "Arbitration mesages must be handled by server");
      case p4v1::StreamMessageRequest::kPacket:
        return packet_io.packet_out_send(request.packet());
      case p4v1::StreamMessageRequest::kDigestAck:
        digest_mgr.ack(request.digest_ack());
        RETURN_OK_STATUS();
      default:
        RETURN_ERROR_STATUS(
            Code::INVALID_ARGUMENT, "Invalid stream message request type");
    }
    assert(0);
    RETURN_ERROR_STATUS(Code::INTERNAL);  // unreachable
  }

  void stream_message_response_register_cb(StreamMessageResponseCb cb,
                                           void *cookie) {
    idle_timeout_register_cb(cb, cookie);
    packet_io.packet_in_register_cb(cb, cookie);
    digest_mgr.stream_message_response_register_cb(cb, cookie);
  }

  Status counter_write(p4v1::Update::Type update,
                       const p4v1::CounterEntry &counter_entry,
                       const SessionTemp &session) {
    if (!check_p4_id(counter_entry.counter_id(), P4Ids::COUNTER))
      return make_invalid_p4_id_status();
    if (!counter_entry.has_index()) {
      RETURN_ERROR_STATUS(
          Code::UNIMPLEMENTED,
          "Wildcard write is not supported for indirect counters yet");
    }
    if (counter_entry.index().index() < 0) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "A negative number is not a valid index value");
    }
    auto index = static_cast<size_t>(counter_entry.index().index());
    switch (update) {
      case p4v1::Update::UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Update type is not set");
      case p4v1::Update::INSERT:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "INSERT update type not supported for counters");
      case p4v1::Update::MODIFY:
        {
          auto pi_counter_data = counter_data_proto_to_pi(
              counter_entry.data(), counter_entry.counter_id());
          auto pi_status = pi_counter_write(session.get(), device_tgt,
                                            counter_entry.counter_id(),
                                            index,
                                            &pi_counter_data);
          if (pi_status != PI_STATUS_SUCCESS)
            RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when writing to counter");
        }
        break;
      case p4v1::Update::DELETE:  // TODO(antonin): return error instead?
        {
          pi_counter_data_t pi_counter_data =
              {PI_COUNTER_UNIT_PACKETS | PI_COUNTER_UNIT_BYTES, 0u, 0u};
          auto pi_status = pi_counter_write(session.get(), device_tgt,
                                            counter_entry.counter_id(),
                                            index,
                                            &pi_counter_data);
          if (pi_status != PI_STATUS_SUCCESS)
            RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when writing to counter");
        }
        break;
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid update type");
    }
    RETURN_OK_STATUS();
  }

  Status direct_counter_write(p4v1::Update::Type update,
                              const p4v1::DirectCounterEntry &counter_entry,
                              const SessionTemp &session) {
    if (!counter_entry.has_table_entry()) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Missing table_entry field in DirectCounterEntry");
    }
    const auto &table_entry = counter_entry.table_entry();
    if (!check_p4_id(table_entry.table_id(), P4Ids::TABLE))
      return make_invalid_p4_id_status();
    if (table_entry.is_default_action()) {
      RETURN_ERROR_STATUS(
          Code::UNIMPLEMENTED,
          "Writing DirectCounterEntry not supported for default entry yet");
    }
    auto table_lock = table_info_store.lock_table(table_entry.table_id());

    pi_entry_handle_t entry_handle = 0;
    {
      auto status = entry_handle_from_table_entry(table_entry, &entry_handle);
      if (IS_ERROR(status)) return status;
    }

    p4_id_t table_direct_counter_id = pi_get_table_direct_resource_p4_id(
        table_entry.table_id(), P4Ids::DIRECT_COUNTER);
    if (table_direct_counter_id == PI_INVALID_ID) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Table has no direct counters");
    }
    switch (update) {
      case p4v1::Update::UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Update type is not set");
      case p4v1::Update::INSERT:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "INSERT update type not supported for counters");
      case p4v1::Update::MODIFY:
        {
          auto pi_counter_data = counter_data_proto_to_pi(
              counter_entry.data(), table_direct_counter_id);
          auto pi_status = pi_counter_write_direct(session.get(), device_tgt,
                                                   table_direct_counter_id,
                                                   entry_handle,
                                                   &pi_counter_data);
          if (pi_status != PI_STATUS_SUCCESS) {
            RETURN_ERROR_STATUS(Code::UNKNOWN,
                                "Error when writing to direct counter");
          }
        }
        break;
      case p4v1::Update::DELETE:  // TODO(antonin): return error instead?
        {
          pi_counter_data_t pi_counter_data =
              {PI_COUNTER_UNIT_PACKETS | PI_COUNTER_UNIT_BYTES, 0u, 0u};
          auto pi_status = pi_counter_write_direct(session.get(), device_tgt,
                                                   table_direct_counter_id,
                                                   entry_handle,
                                                   &pi_counter_data);
          if (pi_status != PI_STATUS_SUCCESS) {
            RETURN_ERROR_STATUS(Code::UNKNOWN,
                                "Error when writing to direct counter");
          }
        }
        break;
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid update type");
    }
    RETURN_OK_STATUS();
  }

  Status counter_read_one(p4_id_t counter_id,
                          const p4v1::CounterEntry &counter_entry,
                          const SessionTemp &session,
                          p4v1::ReadResponse *response) const {
    assert(pi_p4info_counter_get_direct(p4info.get(), counter_id) ==
           PI_INVALID_ID);
    if (counter_entry.has_index()) {
      if (counter_entry.index().index() < 0) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "A negative number is not a valid index value");
      }
      auto entry = response->add_entities()->mutable_counter_entry();
      entry->CopyFrom(counter_entry);
      return counter_read_one_index(session, counter_id, entry, true);
    }
    // default index, read all
    auto counter_size = pi_p4info_counter_get_size(p4info.get(), counter_id);
    {  // sync the entire counter array with HW
      auto pi_status = pi_counter_hw_sync(
          session.get(), device_tgt, counter_id, NULL, NULL);
      if (pi_status != PI_STATUS_SUCCESS)
        RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when doing HW counter sync");
    }
    for (size_t index = 0; index < counter_size; index++) {
      auto entry = response->add_entities()->mutable_counter_entry();
      entry->set_counter_id(counter_id);
      auto index_msg = entry->mutable_index();
      index_msg->set_index(index);
      auto status = counter_read_one_index(session, counter_id, entry);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status counter_read(const p4v1::CounterEntry &counter_entry,
                      const SessionTemp &session,
                      p4v1::ReadResponse *response) const {
    auto counter_id = counter_entry.counter_id();
    if (counter_id == 0) {  // read all entries for all counters
      for (auto c_id = pi_p4info_counter_begin(p4info.get());
           c_id != pi_p4info_counter_end(p4info.get());
           c_id = pi_p4info_counter_next(p4info.get(), c_id)) {
        if (pi_p4info_counter_get_direct(p4info.get(), c_id) != PI_INVALID_ID)
          continue;
        auto status = counter_read_one(c_id, counter_entry, session, response);
        if (IS_ERROR(status)) return status;
      }
    } else {  // read for a single counter
      if (!check_p4_id(counter_id, P4Ids::COUNTER))
        return make_invalid_p4_id_status();
      if (pi_p4info_counter_get_direct(p4info.get(), counter_id) !=
          PI_INVALID_ID) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Cannot use CounterEntry with a direct counter");
      }
      auto status = counter_read_one(
          counter_id, counter_entry, session, response);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status direct_counter_read_one(const p4v1::TableEntry &table_entry,
                                 const SessionTemp &session,
                                 p4v1::ReadResponse *response) const {
    if (!table_entry.match().empty()) {
      auto table_lock = table_info_store.lock_table(table_entry.table_id());

      pi_entry_handle_t entry_handle = 0;
      {
        auto status = entry_handle_from_table_entry(table_entry, &entry_handle);
        if (IS_ERROR(status)) return status;
      }
      p4_id_t table_direct_counter_id = pi_get_table_direct_resource_p4_id(
        table_entry.table_id(), P4Ids::DIRECT_COUNTER);
      if (table_direct_counter_id == PI_INVALID_ID) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Table has no direct counters");
      }
      pi_counter_data_t counter_data;
      auto pi_status = pi_counter_read_direct(
          session.get(), device_tgt, table_direct_counter_id, entry_handle,
          PI_COUNTER_FLAGS_HW_SYNC, &counter_data);
      if (pi_status != PI_STATUS_SUCCESS) {
        RETURN_ERROR_STATUS(Code::UNKNOWN,
                            "Error when reading counter from target");
      }
      auto entry = response->add_entities()->mutable_direct_counter_entry();
      entry->mutable_table_entry()->CopyFrom(table_entry);
      counter_data_pi_to_proto(counter_data, entry->mutable_data());
      RETURN_OK_STATUS();
    }
    // read all direct counters in table
    RETURN_ERROR_STATUS(
        Code::UNIMPLEMENTED,
        "Reading ALL direct counters in a table is not supported yet");
  }

  Status direct_counter_read(const p4v1::DirectCounterEntry &counter_entry,
                             const SessionTemp &session,
                             p4v1::ReadResponse *response) const {
    if (!counter_entry.has_table_entry()) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Missing table_entry field in DirectCounterEntry");
    }
    const auto &table_entry = counter_entry.table_entry();
    if (table_entry.table_id() == 0) {
      RETURN_ERROR_STATUS(
          Code::UNIMPLEMENTED,
          "Reading ALL direct counters for all tables is not supported yet");
    }
    if (!check_p4_id(table_entry.table_id(), P4Ids::TABLE))
      return make_invalid_p4_id_status();
    if (table_entry.is_default_action()) {
      RETURN_ERROR_STATUS(
          Code::UNIMPLEMENTED,
          "Reading DirectCounterEntry not supported for default entry yet");
    }
    return direct_counter_read_one(table_entry, session, response);
  }

  Status pre_mc_write(p4v1::Update::Type update,
                      const p4v1::MulticastGroupEntry &mc_group_entry) {
    if (mc_group_entry.multicast_group_id() >=
        PreMcMgr::first_reserved_group_id()) {
      RETURN_ERROR_STATUS(Code::OUT_OF_RANGE, "Group id value is too high");
    }
    switch (update) {
      case p4v1::Update::UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Update type is not set");
      case p4v1::Update::INSERT:
        return pre_mc_mgr->group_create(mc_group_entry);
      case p4v1::Update::MODIFY:
        return pre_mc_mgr->group_modify(mc_group_entry);
      case p4v1::Update::DELETE:
        return pre_mc_mgr->group_delete(mc_group_entry);
      default:
        break;
    }
    RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid update type");
  }

  Status pre_clone_write(p4v1::Update::Type update,
                         const p4v1::CloneSessionEntry &clone_session_entry,
                         const SessionTemp &session) {
    switch (update) {
      case p4v1::Update::UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Update type is not set");
      case p4v1::Update::INSERT:
        return pre_clone_mgr->session_create(clone_session_entry, session);
      case p4v1::Update::MODIFY:
        return pre_clone_mgr->session_modify(clone_session_entry, session);
      case p4v1::Update::DELETE:
        return pre_clone_mgr->session_delete(clone_session_entry, session);
      default:
        break;
    }
    RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid update type");
  }

  Status pre_write(p4v1::Update::Type update,
                   const p4v1::PacketReplicationEngineEntry &pre_entry,
                   const SessionTemp &session) {
    using PreEntry = p4v1::PacketReplicationEngineEntry;
    switch (pre_entry.type_case()) {
      case PreEntry::kMulticastGroupEntry:
        // PI uses a different session for multicast operations
        return pre_mc_write(update, pre_entry.multicast_group_entry());
      case PreEntry::kCloneSessionEntry:
        return pre_clone_write(
            update, pre_entry.clone_session_entry(), session);
      default:
        break;
    }
    RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid PRE operation");
  }

  static void init(size_t max_devices) {
    auto pi_status = pi_init(max_devices, NULL);
    (void) pi_status;
    assert(pi_status == PI_STATUS_SUCCESS);
  }

  static void destroy() {
    pi_destroy();
  }

 private:
  // internal version of read, which does not acquire an exclusive lock
  Status read_(const p4v1::ReadRequest &request,
               p4v1::ReadResponse *response) const {
    Status status;
    status.set_code(Code::OK);
    for (const auto &entity : request.entities()) {
      status = read_one_(entity, response);
      if (status.code() != Code::OK) break;
    }
    return status;
  }

  // internal version of read_one, which does not acquire an exclusive lock
  Status read_one_(const p4v1::Entity &entity,
                   p4v1::ReadResponse *response) const {
    Status status;
    SessionTemp session(false  /* = batch */);
    switch (entity.entity_case()) {
      case p4v1::Entity::kTableEntry:
        status = table_read(entity.table_entry(), session, response);
        break;
      case p4v1::Entity::kActionProfileMember:
        status = action_profile_member_read(
            entity.action_profile_member(), session, response);
        break;
      case p4v1::Entity::kActionProfileGroup:
        status = action_profile_group_read(
            entity.action_profile_group(), session, response);
        break;
      case p4v1::Entity::kMeterEntry:
        status = meter_read(entity.meter_entry(), session, response);
        break;
      case p4v1::Entity::kDirectMeterEntry:
        status = direct_meter_read(
            entity.direct_meter_entry(), session, response);
        break;
      case p4v1::Entity::kCounterEntry:
        status = counter_read(entity.counter_entry(), session, response);
        break;
      case p4v1::Entity::kDirectCounterEntry:
        status = direct_counter_read(
            entity.direct_counter_entry(), session, response);
        break;
      case p4v1::Entity::kPacketReplicationEngineEntry:
        status = ERROR_STATUS(Code::UNIMPLEMENTED,
                              "Reading from PRE is not supported yet");
        break;
      case p4v1::Entity::kValueSetEntry:  // TODO(antonin)
        status = ERROR_STATUS(Code::UNIMPLEMENTED,
                              "ValueSet reads are not supported yet");
        break;
      case p4v1::Entity::kRegisterEntry:
        status = ERROR_STATUS(Code::UNIMPLEMENTED,
                              "Register reads are not supported yet");
        break;
      case p4v1::Entity::kDigestEntry:
        status = digest_mgr.config_read(entity.digest_entry(), response);
        break;
      default:
        status = ERROR_STATUS(Code::UNKNOWN, "Incorrect entity type");
        break;
    }
    return status;
  }

  // internal version of write, which does not acquire a shared lock
  Status write_(const p4v1::WriteRequest &request) {
    if (request.atomicity() != p4v1::WriteRequest::CONTINUE_ON_ERROR) {
      RETURN_ERROR_STATUS(
          Code::UNIMPLEMENTED,
          "Support for atomic write modes has not been implemented yet");
    }
    Status status;
    status.set_code(Code::OK);
    SessionTemp session(true  /* = batch */);
    P4ErrorReporter error_reporter;
    for (const auto &update : request.updates()) {
      const auto &entity = update.entity();
      switch (entity.entity_case()) {
        case p4v1::Entity::kExternEntry:
          Logger::get()->error("No extern support yet");
          status.set_code(Code::UNIMPLEMENTED);
          break;
        case p4v1::Entity::kTableEntry:
          status = table_write(update.type(), entity.table_entry(), &session);
          break;
        case p4v1::Entity::kActionProfileMember:
          status = action_profile_member_write(
              update.type(), entity.action_profile_member(), session);
          break;
        case p4v1::Entity::kActionProfileGroup:
          status = action_profile_group_write(
              update.type(), entity.action_profile_group(), session);
          break;
        case p4v1::Entity::kMeterEntry:
          status = meter_write(update.type(), entity.meter_entry(), session);
          break;
        case p4v1::Entity::kDirectMeterEntry:
          status = direct_meter_write(
              update.type(), entity.direct_meter_entry(), session);
          break;
        case p4v1::Entity::kCounterEntry:
          status = counter_write(
              update.type(), entity.counter_entry(), session);
          break;
        case p4v1::Entity::kDirectCounterEntry:
          status = direct_counter_write(
              update.type(), entity.direct_counter_entry(), session);
          break;
        case p4v1::Entity::kPacketReplicationEngineEntry:
          status = pre_write(update.type(),
                             entity.packet_replication_engine_entry(),
                             session);
          break;
        case p4v1::Entity::kValueSetEntry:  // TODO(antonin)
          status = ERROR_STATUS(Code::UNIMPLEMENTED,
                                "ValueSet writes are not supported yet");
          break;
        case p4v1::Entity::kRegisterEntry:
          status = ERROR_STATUS(Code::UNIMPLEMENTED,
                                "Register writes are not supported yet");
          break;
        case p4v1::Entity::kDigestEntry:
          status = digest_mgr.config_write(
              entity.digest_entry(), update.type(), session);
          break;
        default:
          status = ERROR_STATUS(Code::UNKNOWN, "Incorrect entity type");
          break;
      }
      auto cleanup_status = session.local_cleanup();
      error_reporter.push_back(
          IS_OK(cleanup_status) ? status : cleanup_status);
    }
    return error_reporter.get_status();
  }

  p4_id_t pi_get_table_direct_resource_p4_id(
      pi_p4_id_t table_id, P4Ids::Prefix resource_type) const {
    size_t num_direct_resources = 0;
    p4_id_t table_direct_resource_id = PI_INVALID_ID;
    const pi_p4_id_t* direct_resource = pi_p4info_table_get_direct_resources(
        p4info.get(), table_id, &num_direct_resources);
    for (size_t i = 0; i < num_direct_resources; i++) {
      if (check_p4_id(direct_resource[i], resource_type)) {
        table_direct_resource_id = direct_resource[i];
        break;
      }
    }
    return table_direct_resource_id;
  }

  bool check_p4_id(p4_id_t p4_id, P4Ids::Prefix expected_type) const {
    return (pi::proto::util::resource_type_from_id(p4_id) == expected_type)
        && pi_p4info_is_valid_id(p4info.get(), p4_id);
  }

  const p4v1::FieldMatch *find_mf(const p4v1::TableEntry &entry,
                                pi_p4_id_t mf_id) const {
    for (const auto &mf : entry.match())
      if (mf.field_id() == mf_id) return &mf;
    return nullptr;
  }

  Status validate_exact_match(const p4v1::FieldMatch::Exact &mf,
                              size_t bitwidth) const {
    if (check_proto_bytestring(mf.value(), bitwidth) != Code::OK)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid bytestring format");
    RETURN_OK_STATUS();
  }

  Status validate_lpm_match(const p4v1::FieldMatch::LPM &mf,
                            size_t bitwidth) const {
    const auto &value = mf.value();
    const auto pLen = mf.prefix_len();
    if (check_proto_bytestring(value, bitwidth) != Code::OK)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid bytestring format");
    if (pLen < 0) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT, "Prefix length cannot be < 0");
    }
    if (static_cast<size_t>(pLen) > bitwidth) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT, "Prefix length cannot be > bitwidth");
    }
    if (pLen == 0) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Invalid reprsentation of 'don't care' LPM match, "
          "omit match field instead of using a prefix length of 0");
    }
    // makes sure that value ends with zeros
    if (!common::check_prefix_trailing_zeros(value, pLen)) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Invalid LPM value, incorrect number of trailing zeros");
    }
    RETURN_OK_STATUS();
  }

  Status validate_ternary_match(const p4v1::FieldMatch::Ternary &mf,
                                size_t bitwidth) const {
    const auto &value = mf.value();
    const auto &mask = mf.mask();
    if (check_proto_bytestring(value, bitwidth) != Code::OK)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid bytestring format");
    if (check_proto_bytestring(mask, bitwidth) != Code::OK)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid bytestring format");
    // makes sure that mask is not 0 (otherwise mf should be omitted)
    if (ternary_match_is_dont_care(mf)) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Invalid representation of 'don't care' ternary match, "
          "omit match field instead of using 0 mask");
    }
    // makes sure that value == value & mask
    assert(value.size() == mask.size());
    for (size_t i = 0; i < value.size(); i++) {
      // parenthesis required because of C operator precedence
      if ((value[i] & mask[i]) != value[i]) {
        RETURN_ERROR_STATUS(
            Code::INVALID_ARGUMENT,
            "Invalid ternary value, make sure value & mask == value");
      }
    }
    RETURN_OK_STATUS();
  }

  Status validate_range_match(const p4v1::FieldMatch::Range &mf,
                              size_t bitwidth) const {
    const auto &low = mf.low();
    const auto &high = mf.high();
    if (check_proto_bytestring(low, bitwidth) != Code::OK)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid bytestring format");
    if (check_proto_bytestring(high, bitwidth) != Code::OK)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid bytestring format");
    assert(low.size() == high.size());
    if (range_match_is_dont_care(mf)) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Invalid representation of 'don't care' range match, "
          "omit match field instead of using low=0 and high=2**bitwidth-1");
    }
    // makes sure that low <= high
    if (std::memcmp(low.data(), high.data(), low.size()) > 0) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Invalid range value, make sure low <= high");
    }
    RETURN_OK_STATUS();
  }

  Status validate_match_key(const p4v1::TableEntry &entry) const {
    auto t_id = entry.table_id();
    size_t num_match_fields;
    auto expected_mf_ids = pi_p4info_table_get_match_fields(
        p4info.get(), t_id, &num_match_fields);
    if (static_cast<size_t>(entry.match().size()) > num_match_fields) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Too many fields in match key");
    }

    Status status;
    int num_mf_matched = 0;  // check if some extra fields in the match key
    // the double loop is potentially too slow; refactor this code if it proves
    // to be a bottleneck
    for (size_t i = 0; i < num_match_fields; i++) {
      auto mf_id = expected_mf_ids[i];
      auto mf_info = pi_p4info_table_match_field_info(p4info.get(), t_id, i);
      auto mf = find_mf(entry, mf_id);
      bool can_be_omitted = (mf_info->match_type == PI_P4INFO_MATCH_TYPE_LPM) ||
          (mf_info->match_type == PI_P4INFO_MATCH_TYPE_TERNARY) ||
          (mf_info->match_type == PI_P4INFO_MATCH_TYPE_RANGE);
      if (mf == nullptr && !can_be_omitted) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Missing non-ternary field in match key");
      }
      if (mf == nullptr) continue;
      num_mf_matched++;
      auto bitwidth = mf_info->bitwidth;
      switch (mf_info->match_type) {
        // For backward-compatibility with old workflow. A P4_14 valid match
        // type is replaced by an exact match in the P4Info, which is why we
        // check that the P4Runtime message includes an exact field in that
        // case.
        case PI_P4INFO_MATCH_TYPE_VALID:
        case PI_P4INFO_MATCH_TYPE_EXACT:
          if (!mf->has_exact())
            RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match type");
          status = validate_exact_match(mf->exact(), bitwidth);
          if (IS_ERROR(status)) return status;
          break;
        case PI_P4INFO_MATCH_TYPE_LPM:
          if (!mf->has_lpm())
            RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match type");
          status = validate_lpm_match(mf->lpm(), bitwidth);
          if (IS_ERROR(status)) return status;
          break;
        case PI_P4INFO_MATCH_TYPE_TERNARY:
          if (!mf->has_ternary())
            RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match type");
          status = validate_ternary_match(mf->ternary(), bitwidth);
          if (IS_ERROR(status)) return status;
          break;
        case PI_P4INFO_MATCH_TYPE_RANGE:
          if (!mf->has_range())
            RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match type");
          status = validate_range_match(mf->range(), bitwidth);
          if (IS_ERROR(status)) return status;
          break;
        default:
          assert(0);
          break;
      }
    }
    if (num_mf_matched != entry.match().size())
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Unknown field in match key");
    RETURN_OK_STATUS();
  }

  Status construct_match_key(const p4v1::TableEntry &entry,
                             pi::MatchKey *match_key) const {
    if (entry.is_default_action()) {
      if (!entry.match().empty()) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Non-empty key for default entry");
      }
      if (entry.priority() != 0) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Non-zero priority for default entry");
      }
      match_key->set_is_default(true);
      RETURN_OK_STATUS();
    }
    auto status = validate_match_key(entry);
    if (IS_ERROR(status)) return status;
    auto t_id = entry.table_id();
    bool need_priority = false;
    size_t num_match_fields;
    auto expected_mf_ids = pi_p4info_table_get_match_fields(
        p4info.get(), t_id, &num_match_fields);
    // same as for validate_match_key above: refactor if double loop too
    // expensive
    for (size_t i = 0; i < num_match_fields; i++) {
      auto mf_id = expected_mf_ids[i];
      auto mf_info = pi_p4info_table_match_field_info(p4info.get(), t_id, i);
      need_priority = need_priority ||
          (mf_info->match_type == PI_P4INFO_MATCH_TYPE_TERNARY) ||
          (mf_info->match_type == PI_P4INFO_MATCH_TYPE_RANGE);
      auto mf = find_mf(entry, mf_id);
      if (mf != nullptr) {
        switch (mf_info->match_type) {
          // For backward-compatibility with old workflow. A P4_14 valid match
          // type is replaced by an exact match in the P4Info, which is why we
          // read the value from the exact field in the P4Runtime message
          // ('\x00' means invalid and every other value means valid).
          case PI_P4INFO_MATCH_TYPE_VALID:
            match_key->set_valid(mf_id,
                                 mf->exact().value() != std::string("\x00", 1));
            break;
          case PI_P4INFO_MATCH_TYPE_EXACT:
            match_key->set_exact(mf_id, mf->exact().value().data(),
                                 mf->exact().value().size());
            break;
          case PI_P4INFO_MATCH_TYPE_LPM:
            match_key->set_lpm(mf_id, mf->lpm().value().data(),
                               mf->lpm().value().size(),
                               mf->lpm().prefix_len());
            break;
          case PI_P4INFO_MATCH_TYPE_TERNARY:
            match_key->set_ternary(mf_id, mf->ternary().value().data(),
                                   mf->ternary().mask().data(),
                                   mf->ternary().value().size());
            break;
          case PI_P4INFO_MATCH_TYPE_RANGE:
            match_key->set_range(mf_id, mf->range().low().data(),
                                 mf->range().high().data(),
                                 mf->range().low().size());
            break;
          default:
            assert(0);
            break;
        }
      } else {  // missing field
        auto bitwidth = mf_info->bitwidth;
        auto nbytes = (bitwidth + 7) / 8;
        switch (mf_info->match_type) {
          case PI_P4INFO_MATCH_TYPE_LPM:
          case PI_P4INFO_MATCH_TYPE_TERNARY:
            // nothing to do: key, mask, pLen default to 0
            break;
          case PI_P4INFO_MATCH_TYPE_RANGE:
            match_key->set_range(mf_id,
                                 common::range_default_lo(bitwidth).data(),
                                 common::range_default_hi(bitwidth).data(),
                                 nbytes);
            break;
          default:
            assert(0);  // cannot reach this because of validate method call
            break;
        }
      }
    }
    if (!need_priority && entry.priority() > 0) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Non-zero priority for non-ternary match");
    } else if (need_priority && entry.priority() == 0) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Zero priority for ternary match");
    } else if (need_priority) {
      match_key->set_priority(entry.priority());
    }
    RETURN_OK_STATUS();
  }

  // Called in table_insert & table_modify
  Status validate_action(const p4v1::TableEntry &entry) const {
    const auto table_id = entry.table_id();
    const auto &table_action = entry.action();
    auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                             table_id);
    auto table_is_indirect = (action_prof_id != PI_INVALID_ID);
    if (table_is_indirect && entry.is_default_action()) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Cannot set / reset default action for indirect table {}", table_id);
    }
    if (entry.is_default_action() &&
        pi_p4info_table_has_const_default_action(p4info.get(), table_id)) {
      RETURN_ERROR_STATUS(
          Code::PERMISSION_DENIED,
          "Cannot set / reset default action for table {} which has a const "
          "default action", table_id);
    }
    if (!entry.has_action()) RETURN_OK_STATUS();
    if (table_is_indirect &&
        table_action.type_case() == p4v1::TableAction::kAction) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Cannot provide direct action for indirect table {}", table_id);
    }
    if (!table_is_indirect &&
        table_action.type_case() != p4v1::TableAction::kAction) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Cannot provide indirect action for direct table {}", table_id);
    }
    // The PSA spec & the P4Runtime spec specify that tables with an action
    // profile implementation cannot define a default action, which means that
    // the rest of the checks are meaningless for indirect tables.
    if (table_is_indirect) RETURN_OK_STATUS();
    auto action_id = table_action.action().action_id();
    if (!check_p4_id(action_id, P4Ids::ACTION))
      return make_invalid_p4_id_status();
    auto action_info = pi_p4info_table_get_action_info(
        p4info.get(), table_id, action_id);
    if (!action_info)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid action for table");
    // most common case
    if (action_info->scope == PI_P4INFO_ACTION_SCOPE_TABLE_AND_DEFAULT)
      RETURN_OK_STATUS();
    if (action_info->scope == PI_P4INFO_ACTION_SCOPE_TABLE_ONLY &&
        entry.is_default_action()) {
      RETURN_ERROR_STATUS(
          Code::PERMISSION_DENIED,
          "Cannot use TABLE_ONLY action as default action");
    }
    if (action_info->scope == PI_P4INFO_ACTION_SCOPE_DEFAULT_ONLY &&
        !entry.is_default_action()) {
      RETURN_ERROR_STATUS(
          Code::PERMISSION_DENIED,
          "Cannot use DEFAULT_ONLY action in table entry");
    }
    RETURN_OK_STATUS();
  }

  Status construct_action_data(uint32_t table_id, const p4v1::Action &action,
                               pi::ActionEntry *action_entry) const {
    (void) table_id;
    auto status = validate_action_data(p4info.get(), action);
    if (IS_ERROR(status)) return status;
    action_entry->init_action_data(p4info.get(), action.action_id());
    auto action_data = action_entry->mutable_action_data();
    for (const auto &p : action.params()) {
      action_data->set_arg(p.param_id(), p.value().data(), p.value().size());
    }
    RETURN_OK_STATUS();
  }

  Status construct_action_entry_indirect(uint32_t table_id,
                                         const p4v1::TableAction &table_action,
                                         pi::ActionEntry *action_entry) {
    auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                             table_id);
    // validate_action checked that table was indirect
    assert(action_prof_id != PI_INVALID_ID);
    auto action_prof_mgr = get_action_prof_mgr(action_prof_id);
    // cannot assert because the action prof id is provided by the PI
    assert(action_prof_mgr);
    pi_indirect_handle_t indirect_h;
    bool found_h;
    switch (table_action.type_case()) {
      case p4v1::TableAction::kActionProfileMemberId:
        found_h = action_prof_mgr->retrieve_member_handle(
            table_action.action_profile_member_id(), &indirect_h);
        break;
      case p4v1::TableAction::kActionProfileGroupId:
        found_h = action_prof_mgr->retrieve_group_handle(
            table_action.action_profile_group_id(), &indirect_h);
        break;
      default:
        assert(0);
    }
    // invalid member/group id
    if (!found_h)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid member / group id");
    action_entry->init_indirect_handle(indirect_h);
    RETURN_OK_STATUS();
  }

  // the table_id is needed for indirect entries
  Status construct_action_entry(uint32_t table_id,
                                const p4v1::TableAction &table_action,
                                pi::ActionEntry *action_entry) {
    switch (table_action.type_case()) {
      case p4v1::TableAction::kAction:
        return construct_action_data(table_id, table_action.action(),
                                     action_entry);
      case p4v1::TableAction::kActionProfileMemberId:
      case p4v1::TableAction::kActionProfileGroupId:
        return construct_action_entry_indirect(table_id, table_action,
                                               action_entry);
      case p4v1::TableAction::kActionProfileActionSet:
        // This case is handled differently because in the one-shot case,
        // constructing the action entry actually requires creating / deleting
        // groups. construct_action_entry_oneshot is called instead.
        RETURN_ERROR_STATUS(Code::INTERNAL,
                            "Unexpected call to construct_action_entry");
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Invalid table action type");
    }
  }

  Status construct_action_entry_oneshot(
      uint32_t table_id,
      const p4v1::ActionProfileActionSet &action_set,
      pi::ActionEntry *action_entry,
      SessionTemp *session) {
    auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                             table_id);
    // validate_action checked that table was indirect
    assert(action_prof_id != PI_INVALID_ID);
    auto action_prof_mgr = get_action_prof_mgr(action_prof_id);
    // cannot assert because the action prof id is provided by the PI
    assert(action_prof_mgr);

    pi_indirect_handle_t group_h;
    RETURN_IF_ERROR(action_prof_mgr->oneshot_group_create(
        action_set, &group_h, session));
    action_entry->init_indirect_handle(group_h);
    session->cleanup_task_push(std::unique_ptr<OneShotCleanup>(
        new OneShotCleanup(action_prof_mgr, group_h)));
    RETURN_OK_STATUS();
  }

  // takes storage for meter_spec and counter_data to enable using stack storage
  Status construct_direct_resources(const p4v1::TableEntry &table_entry,
                                    pi::ActionEntry *action_entry,
                                    pi_meter_spec_t *meter_spec,
                                    pi_counter_data_t *counter_data) {
    if (table_entry.has_meter_config()) {
      p4_id_t meter_id = pi_get_table_direct_resource_p4_id(
          table_entry.table_id(), P4Ids::DIRECT_METER);
      if (meter_id == PI_INVALID_ID) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Table has no direct meters");
      }
      auto status = validate_meter_spec(table_entry.meter_config());
      if (IS_ERROR(status)) return status;
      *meter_spec = meter_spec_proto_to_pi(
          table_entry.meter_config(), meter_id);
      action_entry->add_direct_res_config(meter_id, meter_spec);
    }

    if (table_entry.has_counter_data()) {
      p4_id_t counter_id = pi_get_table_direct_resource_p4_id(
          table_entry.table_id(), P4Ids::DIRECT_COUNTER);
      if (counter_id == PI_INVALID_ID) {
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "Table has no direct counters");
      }
      *counter_data = counter_data_proto_to_pi(
          table_entry.counter_data(), counter_id);
      action_entry->add_direct_res_config(counter_id, counter_data);
    }

    RETURN_OK_STATUS();
  }

  // returns true if table supports idle timeout.
  // returns an error if idle_timeout_ns is not valid.
  StatusOr<bool> validate_entry_ttl(const p4v1::TableEntry &table_entry) {
    if (table_entry.idle_timeout_ns() < 0) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "idle_timeout_ns must be a positive value");
    }
    bool supports_idle_timeout = pi_p4info_table_supports_idle_timeout(
        p4info.get(), table_entry.table_id());
    if (table_entry.idle_timeout_ns() > 0 && !supports_idle_timeout) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "idle_timeout_ns must be set to 0 for tables which do not support "
          "idle timeout");
    }
    return supports_idle_timeout;
  }

  // call this only if validate_entry_ttl succeeds and returns true.
  // we only set the ttl in the PI table entry if it's an INSERT of if it's a
  // MODIFY and the new value is different from the old one.
  void set_entry_ttl(const p4v1::TableEntry &table_entry,
                     pi::ActionEntry *action_entry,
                     int64_t *previous_ttl  /* nullptr for INSERT */) {
    if (previous_ttl == nullptr ||
        (*previous_ttl != table_entry.idle_timeout_ns())) {
      action_entry->set_ttl(
          static_cast<uint64_t>(table_entry.idle_timeout_ns()));
    }
  }

  Status table_insert(const p4v1::TableEntry &table_entry,
                      SessionTemp *session) {
    const auto table_id = table_entry.table_id();
    if (table_entry.is_default_action()) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Cannot use INSERT for default entry");
    }

    if (!table_entry.has_action())
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "'action' field must be set");

    pi::MatchKey match_key(p4info.get(), table_id);
    {
      auto status = construct_match_key(table_entry, &match_key);
      if (IS_ERROR(status)) return status;
    }

    RETURN_IF_ERROR(validate_action(table_entry));

    pi::ActionEntry action_entry;
    pi_meter_spec_t _meter_spec_storage;
    pi_counter_data_t _counter_data_storage;
    if (table_entry.action().type_case() ==
        p4v1::TableAction::kActionProfileActionSet) {
      session->cleanup_scope_push();
      RETURN_IF_ERROR(construct_action_entry_oneshot(
          table_id,
          table_entry.action().action_profile_action_set(),
          &action_entry,
          session));
    } else {
      RETURN_IF_ERROR(construct_action_entry(
          table_id, table_entry.action(), &action_entry));
    }
    RETURN_IF_ERROR(construct_direct_resources(
        table_entry, &action_entry,
        &_meter_spec_storage, &_counter_data_storage));

    StatusOr<bool> supports_idle_timeout = validate_entry_ttl(table_entry);
    RETURN_IF_ERROR(supports_idle_timeout.status());
    if (supports_idle_timeout.ValueOrDie())
      set_entry_ttl(table_entry, &action_entry, nullptr);

    auto table_lock = table_info_store.lock_table(table_id);

    if (table_info_store.get_entry(table_id, match_key) != nullptr) {
      RETURN_ERROR_STATUS(
          Code::ALREADY_EXISTS,
          "Match entry exists, use MODIFY if you wish to change action");
    }

    pi::MatchTable mt(session->get(), device_tgt, p4info.get(), table_id);
    pi_entry_handle_t handle;
    auto pi_status = mt.entry_add(match_key, action_entry, false, &handle);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when adding match entry to target");
    }

    if (table_entry.action().type_case() ==
        p4v1::TableAction::kActionProfileActionSet) {
      table_info_store.add_entry(
          table_id, match_key,
          TableInfoStore::Data(handle, table_entry.controller_metadata(),
                               table_entry.idle_timeout_ns(),
                               action_entry.indirect_handle()));
      session->cleanup_scope_pop();
    } else {
      table_info_store.add_entry(
          table_id, match_key,
          TableInfoStore::Data(handle, table_entry.controller_metadata(),
                               table_entry.idle_timeout_ns()));
    }

    RETURN_OK_STATUS();
  }

  Status table_modify(const p4v1::TableEntry &table_entry,
                      SessionTemp *session) {
    const auto table_id = table_entry.table_id();
    pi::MatchKey match_key(p4info.get(), table_id);
    {
      auto status = construct_match_key(table_entry, &match_key);
      if (IS_ERROR(status)) return status;
    }

    RETURN_IF_ERROR(validate_action(table_entry));

    pi::ActionEntry action_entry;
    pi_meter_spec_t _meter_spec_storage;
    pi_counter_data_t _counter_data_storage;
    if (table_entry.has_action()) {
      if (table_entry.action().type_case() ==
          p4v1::TableAction::kActionProfileActionSet) {
        session->cleanup_scope_push();
        RETURN_IF_ERROR(construct_action_entry_oneshot(
            table_id,
            table_entry.action().action_profile_action_set(),
            &action_entry,
            session));
      } else {
        RETURN_IF_ERROR(construct_action_entry(
            table_id, table_entry.action(), &action_entry));
      }
    } else if (!table_entry.is_default_action()) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "'action' field must be set for non-default entries");
    }
    RETURN_IF_ERROR(construct_direct_resources(
        table_entry, &action_entry,
        &_meter_spec_storage, &_counter_data_storage));
    // Perform checks without the lock, then do the actual set in action_entry
    // while holding the lock (since the operation requires knowing the previous
    // TTL value).
    StatusOr<bool> supports_idle_timeout = validate_entry_ttl(table_entry);
    RETURN_IF_ERROR(supports_idle_timeout.status());

    auto table_lock = table_info_store.lock_table(table_id);
    // we need this pointer to update the controller metadata and the one-shot
    // group handle (if needed) if the modify operation is successful
    auto entry_data = table_info_store.get_entry(table_id, match_key);

    if (entry_data == nullptr)
      RETURN_ERROR_STATUS(Code::NOT_FOUND, "Cannot find match entry");

    if (supports_idle_timeout.ValueOrDie())
      set_entry_ttl(table_entry, &action_entry, nullptr);

    pi::MatchTable mt(session->get(), device_tgt, p4info.get(), table_id);
    pi_status_t pi_status;
    if (table_entry.is_default_action()) {
      if (table_entry.has_action())
        pi_status = mt.default_entry_set(action_entry);
      else
        pi_status = mt.default_entry_reset();
    } else {
      pi_status = mt.entry_modify_wkey(match_key, action_entry);
    }
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when modifying match entry in target");
    }

    if (!table_entry.has_action()) {
      // cannot be false as the function returns early with an error otherwise
      assert(table_entry.is_default_action());
      entry_data->controller_metadata = 0;
      entry_data->idle_timeout_ns = 0;
    } else {
      entry_data->controller_metadata = table_entry.controller_metadata();
      entry_data->idle_timeout_ns = table_entry.idle_timeout_ns();
      if (table_entry.action().type_case() ==
          p4v1::TableAction::kActionProfileActionSet) {
        assert(entry_data->is_oneshot);
        auto *task = session->cleanup_task_back();
        // match entry add was successful: we need to cancel the new group
        // deletion and schedule the deletion of the old group instead
        dynamic_cast<OneShotCleanup *>(task)->update_group_h(
            entry_data->oneshot_group_handle);
        entry_data->oneshot_group_handle = action_entry.indirect_handle();
      }
    }

    RETURN_OK_STATUS();
  }

  Status table_delete(const p4v1::TableEntry &table_entry,
                      SessionTemp *session) {
    const auto table_id = table_entry.table_id();
    if (table_entry.is_default_action()) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Cannot use DELETE for default entry");
    }

    pi::MatchKey match_key(p4info.get(), table_id);
    {
      auto status = construct_match_key(table_entry, &match_key);
      if (IS_ERROR(status)) return status;
    }

    auto table_lock = table_info_store.lock_table(table_id);
    // we need this pointer to access the one-shot group handle (if needed for
    // this entry).
    auto entry_data = table_info_store.get_entry(table_id, match_key);
    if (entry_data == nullptr)
      RETURN_ERROR_STATUS(Code::NOT_FOUND, "Cannot find match entry");

    pi::MatchTable mt(session->get(), device_tgt, p4info.get(), table_id);
    auto pi_status = mt.entry_delete_wkey(match_key);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when deleting match entry in target");
    }

    if (entry_data->is_oneshot) {
      auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                               table_id);
      auto action_prof_mgr = get_action_prof_mgr(action_prof_id);
      assert(action_prof_mgr);
      session->cleanup_scope_push();
      session->cleanup_task_push(std::unique_ptr<OneShotCleanup>(
          new OneShotCleanup(
              action_prof_mgr, entry_data->oneshot_group_handle)));
    }

    table_info_store.remove_entry(table_id, match_key);

    RETURN_OK_STATUS();
  }

  ActionProfMgr *get_action_prof_mgr(uint32_t id) const {
    auto it = action_profs.find(id);
    return (it == action_profs.end()) ? nullptr : it->second.get();
  }

  void counter_data_pi_to_proto(const pi_counter_data_t &pi_data,
                                p4v1::CounterData *data) const {
    if (pi_data.valid & PI_COUNTER_UNIT_PACKETS)
      data->set_packet_count(pi_data.packets);
    if (pi_data.valid & PI_COUNTER_UNIT_BYTES)
      data->set_byte_count(pi_data.bytes);
  }

  pi_counter_data_t counter_data_proto_to_pi(const p4v1::CounterData &data,
                                             pi_p4_id_t counter_id) const {
    pi_counter_data_t pi_data;
    switch (pi_p4info_counter_get_unit(p4info.get(), counter_id)) {
      case PI_P4INFO_COUNTER_UNIT_BYTES:
        pi_data.valid = PI_COUNTER_UNIT_BYTES;
        pi_data.bytes = data.byte_count();
        break;
      case PI_P4INFO_COUNTER_UNIT_PACKETS:
        pi_data.valid = PI_COUNTER_UNIT_PACKETS;
        pi_data.packets = data.packet_count();
        break;
      case PI_P4INFO_COUNTER_UNIT_BOTH:
        pi_data.valid = PI_COUNTER_UNIT_BYTES | PI_COUNTER_UNIT_PACKETS;
        pi_data.bytes = data.byte_count();
        pi_data.packets = data.packet_count();
        break;
    }
    return pi_data;
  }

  static Status validate_meter_spec(const p4v1::MeterConfig &config) {
    // as per P4Runtime spec, -1 is a valid value and means that the packet is
    // always marked "green"
    if (config.cir() < 0 && config.cir() != -1)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Negative meter CIR");
    if (config.cburst() < 0 && config.cburst() != -1)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Negative meter CBurst");
    if (config.pir() < 0 && config.cir() != -1)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Negative meter PIR");
    if (config.pburst() < 0 && config.pburst() != -1)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Negative meter PBurst");
    auto max_burst = std::numeric_limits<uint32_t>::max();
    if (config.cburst() > static_cast<decltype(config.cburst())>(max_burst))
      RETURN_ERROR_STATUS(Code::UNIMPLEMENTED, "CBurst too large");
    if (config.pburst() > static_cast<decltype(config.pburst())>(max_burst))
      RETURN_ERROR_STATUS(Code::UNIMPLEMENTED, "Pburst too large");
    RETURN_OK_STATUS();
  }

  pi_meter_spec_t meter_spec_proto_to_pi(const p4v1::MeterConfig &config,
                                         pi_p4_id_t meter_id) const {
    pi_meter_spec_t pi_meter_spec;
    pi_meter_spec.cir = static_cast<uint64_t>(config.cir());
    pi_meter_spec.cburst = static_cast<uint32_t>(config.cburst());
    pi_meter_spec.pir = static_cast<uint64_t>(config.pir());
    pi_meter_spec.pburst = static_cast<uint32_t>(config.pburst());
    // pi_meter_spec.meter_unit = PI_METER_UNIT_DEFAULT;
    pi_meter_spec.meter_unit =
        (pi_meter_unit_t)pi_p4info_meter_get_unit(p4info.get(), meter_id);
    // pi_meter_spec.meter_type = PI_METER_TYPE_DEFAULT;
    pi_meter_spec.meter_type =
        (pi_meter_type_t)pi_p4info_meter_get_type(p4info.get(), meter_id);
    return pi_meter_spec;
  }

  void meter_spec_pi_to_proto(const pi_meter_spec_t &pi_meter_spec,
                              p4v1::MeterConfig *config) const {
    config->set_cir(pi_meter_spec.cir);
    if (pi_meter_spec.cburst == static_cast<decltype(pi_meter_spec.cburst)>(-1))
      config->set_cburst(-1);
    else
      config->set_cburst(pi_meter_spec.cburst);
    config->set_pir(pi_meter_spec.pir);
    if (pi_meter_spec.pburst == static_cast<decltype(pi_meter_spec.pburst)>(-1))
      config->set_pburst(-1);
    else
      config->set_pburst(pi_meter_spec.pburst);
  }

  Status counter_read_one_index(const SessionTemp &session, uint32_t counter_id,
                                p4v1::CounterEntry *entry,
                                bool hw_sync = false) const {
    // checked by caller
    assert(entry->has_index() && entry->index().index() >= 0);
    auto index = static_cast<size_t>(entry->index().index());
    int flags = hw_sync ? PI_COUNTER_FLAGS_HW_SYNC : PI_COUNTER_FLAGS_NONE;
    pi_counter_data_t counter_data;
    pi_status_t pi_status = pi_counter_read(session.get(), device_tgt,
                                            counter_id, index, flags,
                                            &counter_data);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when reading counter from target");
    }
    counter_data_pi_to_proto(counter_data, entry->mutable_data());
    RETURN_OK_STATUS();
  }

  Status meter_read_one_index(const SessionTemp &session, uint32_t meter_id,
                              p4v1::MeterEntry *entry) const {
    // checked by caller
    assert(entry->has_index() && entry->index().index() >= 0);
    auto index = static_cast<size_t>(entry->index().index());
    pi_meter_spec_t meter_spec;
    pi_status_t pi_status = pi_meter_read(session.get(), device_tgt,
                                          meter_id, index, &meter_spec);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when reading meter spec from target");
    }
    meter_spec_pi_to_proto(meter_spec, entry->mutable_config());
    RETURN_OK_STATUS();
  }

  void idle_timeout_register_cb(StreamMessageResponseCb cb, void *cookie) {
    idle_timeout_buffer.stream_message_response_register_cb(cb, cookie);
    pi_table_idle_timeout_register_cb(
        device_id, &DeviceMgrImp::idle_timeout_cb, static_cast<void *>(this));
  }

  static void idle_timeout_cb(
      pi_dev_id_t dev_id, p4_id_t table_id,
      const pi_match_key_t *match_key, pi_entry_handle_t handle,
      void *cookie) {
    (void) handle;
    auto *device_mgr = static_cast<DeviceMgrImp *>(cookie);
    if (dev_id != device_mgr->device_id) {
      Logger::get()->error("Idle timeout notification does not match device");
      return;
    }
    pi::MatchKey mk(device_mgr->p4info.get(), table_id);
    mk.from(match_key);
    // move match key to avoid extra copies
    device_mgr->idle_timeout_buffer.handle_notification(
        table_id, std::move(mk));
  }

  // Saves the existing forwarding state as one ReadResponse message; meant to
  // be used for the RECONCILE_AND_COMMIT mode of SetForwardingPipeline.
  // We assume that the exclusive lock has been acquired by the caller, which is
  // why is call the internal version of read.
  // The order of the read is important: to avoid dependency issues, we want to
  // make sure that when the state is replayed we populate action profiles
  // before match-action tables. This relies on our knowledge of the rest of the
  // implementation, since we know that the read operations will be done in
  // order.
  Status save_forwarding_state(p4v1::ReadResponse *response) {
    p4v1::ReadRequest request;
    // setting the device id is not really necessary since DeviceMgr::Read does
    // not check it (check is done by the server)
    request.set_device_id(device_id);
    {
      auto *entity = request.add_entities();
      entity->mutable_action_profile_member();
    }
    {
      auto *entity = request.add_entities();
      entity->mutable_action_profile_group();
    }
    {
      auto *entity = request.add_entities();
      entity->mutable_table_entry();
    }
    {
      auto *entity = request.add_entities();
      entity->mutable_meter_entry();
    }
    {
      auto *entity = request.add_entities();
      entity->mutable_counter_entry();
    }
    return read_(request, response);
  }

#ifdef USE_ABSL
  using SharedMutex = absl::Mutex;
  using SharedLock = ReaderMutexLock;
  using UniqueLock = WriterMutexLock;

  #define _ACQUIRE_LOCK

  SharedLock shared_lock() const { return SharedLock(&shared_mutex); }
  UniqueLock unique_lock() const { return UniqueLock(&shared_mutex); }
#else
  using SharedMutex = boost::shared_mutex;
  using SharedLock = boost::shared_lock<SharedMutex>;
  using UniqueLock = boost::unique_lock<SharedMutex>;

  SharedLock shared_lock() const { return SharedLock(shared_mutex); }
  UniqueLock unique_lock() const { return UniqueLock(shared_mutex); }
#endif

  device_id_t device_id;
  // for now, we assume all possible pipes of device are programmed in the same
  // way
  pi_dev_tgt_t device_tgt;

  bool is_config_set{false};
  p4configv1::P4Info p4info_proto;
  bool has_config_cookie{false};
  p4v1::ForwardingPipelineConfig::Cookie config_cookie;
  ConfigFile saved_device_config;

  P4InfoWrapper p4info{nullptr, p4info_deleter};

  TableInfoStore table_info_store;

  PacketIOMgr packet_io;

  DigestMgr digest_mgr;

  // has non-owning pointer to table_info_store
  IdleTimeoutBuffer idle_timeout_buffer;

  // ActionProfMgr is not movable because of mutex
  std::unordered_map<pi_p4_id_t, std::unique_ptr<ActionProfMgr> >
  action_profs{};

  std::unique_ptr<PreMcMgr> pre_mc_mgr;
  std::unique_ptr<PreCloneMgr> pre_clone_mgr;

  mutable SharedMutex shared_mutex{};
};

DeviceMgr::DeviceMgr(device_id_t device_id) {
  pimp = std::unique_ptr<DeviceMgrImp>(new DeviceMgrImp(device_id));
}

DeviceMgr::~DeviceMgr() { }

// PIMPL forwarding

Status
DeviceMgr::pipeline_config_set(
    p4v1::SetForwardingPipelineConfigRequest::Action action,
    const p4v1::ForwardingPipelineConfig &config) {
  return pimp->pipeline_config_set(action, config);
}

Status
DeviceMgr::pipeline_config_get(
    p4v1::GetForwardingPipelineConfigRequest::ResponseType response_type,
    p4v1::ForwardingPipelineConfig *config) {
  return pimp->pipeline_config_get(response_type, config);
}

Status
DeviceMgr::write(const p4v1::WriteRequest &request) {
  return pimp->write(request);
}

Status
DeviceMgr::read(const p4v1::ReadRequest &request,
                p4v1::ReadResponse *response) const {
  return pimp->read(request, response);
}

Status
DeviceMgr::read_one(const p4v1::Entity &entity,
                    p4v1::ReadResponse *response) const {
  return pimp->read_one(entity, response);
}

Status
DeviceMgr::stream_message_request_handle(
    const p4::v1::StreamMessageRequest &request) {
  return pimp->stream_message_request_handle(request);
}

void
DeviceMgr::stream_message_response_register_cb(StreamMessageResponseCb cb,
                                               void *cookie) {
  return pimp->stream_message_response_register_cb(std::move(cb), cookie);
}

void
DeviceMgr::init(size_t max_devices) {
  DeviceMgrImp::init(max_devices);
}

void
DeviceMgr::destroy() {
  DeviceMgrImp::destroy();
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
