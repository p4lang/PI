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

#include <PI/frontends/cpp/tables.h>
#include <PI/frontends/proto/device_mgr.h>
#include <PI/pi.h>
#include <PI/proto/util.h>

#include <memory>
#include <string>
#include <vector>

#include "google/rpc/code.pb.h"

#include "action_helpers.h"
#include "action_prof_mgr.h"
#include "common.h"
#include "p4info_to_and_from_proto.h"  // for p4info_proto_reader
#include "packet_io_mgr.h"
#include "report_error.h"
#include "table_info_store.h"

#include "p4/tmp/p4config.pb.h"

namespace pi {

namespace fe {

namespace proto {

using device_id_t = DeviceMgr::device_id_t;
using p4_id_t = DeviceMgr::p4_id_t;
using Status = DeviceMgr::Status;
using PacketInCb = DeviceMgr::PacketInCb;
using Code = ::google::rpc::Code;
using common::SessionTemp;
using common::check_proto_bytestring;
using common::make_invalid_p4_id_status;
using pi::proto::util::P4ResourceType;

// We don't yet have a mapping from PI error codes to ::google::rpc::Code
// values, so for now we almost always return UNKNOWN. It is likely that we will
// have our own error namespace (in addition to ::google::rpc::Code) anyway.

namespace {

// wraps the p4info pointer provided by the PI library into a unique_ptr
auto p4info_deleter = [](pi_p4info_t *p4info) {
  pi_destroy_config(p4info);
};
using P4InfoWrapper = std::unique_ptr<pi_p4info_t, decltype(p4info_deleter)>;

pi_meter_spec_t meter_spec_proto_to_pi(const p4::MeterConfig &config) {
  pi_meter_spec_t pi_meter_spec;
  pi_meter_spec.cir = static_cast<uint64_t>(config.cir());
  pi_meter_spec.cburst = static_cast<uint32_t>(config.cburst());
  pi_meter_spec.pir = static_cast<uint64_t>(config.pir());
  pi_meter_spec.pburst = static_cast<uint32_t>(config.pburst());
  pi_meter_spec.meter_unit = PI_METER_UNIT_DEFAULT;
  pi_meter_spec.meter_type = PI_METER_TYPE_DEFAULT;
  return pi_meter_spec;
}

}  // namespace

class DeviceMgrImp {
 public:
  explicit DeviceMgrImp(device_id_t device_id)
      : device_id(device_id),
        device_tgt({static_cast<pi_dev_id_t>(device_id), 0xffff}),
        packet_io(device_id) { }

  ~DeviceMgrImp() {
    pi_remove_device(device_id);
  }

  // we assume that the DeviceMgr client is smart enough here: for p4info
  // updates we do not do any locking; we assume that the client will not issue
  // table commands... while updating p4info
  void p4_change(const p4::config::P4Info &p4info_proto_new,
                 pi_p4info_t *p4info_new) {
    table_info_store.reset();
    for (auto t_id = pi_p4info_table_begin(p4info_new);
         t_id != pi_p4info_table_end(p4info_new);
         t_id = pi_p4info_table_next(p4info_new, t_id)) {
      table_info_store.add_table(t_id);
    }

    action_profs.clear();
    for (auto act_prof_id = pi_p4info_act_prof_begin(p4info_new);
         act_prof_id != pi_p4info_act_prof_end(p4info_new);
         act_prof_id = pi_p4info_act_prof_next(p4info_new, act_prof_id)) {
      std::unique_ptr<ActionProfMgr> mgr(
          new ActionProfMgr(device_tgt, act_prof_id, p4info_new));
      action_profs.emplace(act_prof_id, std::move(mgr));
    }

    packet_io.p4_change(p4info_proto_new);

    // we do this last, so that the ActProfMgr instances never point to an
    // invalid p4info, even though this is not strictly required here
    p4info.reset(p4info_new);
    p4info_proto.CopyFrom(p4info_proto_new);
  }

  Status pipeline_config_set(p4::SetForwardingPipelineConfigRequest_Action a,
                             const p4::ForwardingPipelineConfig &config) {
    pi_status_t pi_status;
    if (a == p4::SetForwardingPipelineConfigRequest_Action_UNSPECIFIED) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Invalid SetForwardingPipeline action");
    }

    pi_p4info_t *p4info_tmp = nullptr;
    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY ||
        a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_SAVE ||
        a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT) {
      if (!pi::p4info::p4info_proto_reader(config.p4info(), &p4info_tmp))
        RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when importing p4info");
    }

    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY)
      RETURN_OK_STATUS();

    p4::tmp::P4DeviceConfig p4_device_config;
    if (!p4_device_config.ParseFromString(config.p4_device_config())) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Invalid 'p4_device_config', not an instance of "
          "p4::tmp::P4DeviceConfig");
    }

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
    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT &&
        p4_device_config.device_data().empty()) {
      if (pi_is_device_assigned(device_id)) remove_device();
      assert(!pi_is_device_assigned(device_id));
      auto assign_options = make_assign_options();
      pi_status = pi_assign_device(device_id, p4info_tmp,
                                   assign_options.data());
      if (pi_status != PI_STATUS_SUCCESS) {
        pi_destroy_config(p4info_tmp);
        RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when assigning device");
      }
      p4_change(config.p4info(), p4info_tmp);
      RETURN_OK_STATUS();
    }

    // assign device if needed, i.e. if device hasn't been assigned yet or if
    // the reassign flag is set
    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_SAVE ||
        a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT) {
      if (pi_is_device_assigned(device_id) && p4_device_config.reassign())
        remove_device();
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

    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_SAVE ||
        a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT) {
      const auto &device_data = p4_device_config.device_data();
      pi_status = pi_update_device_start(device_id, p4info_tmp,
                                         device_data.data(),
                                         device_data.size());
      if (pi_status != PI_STATUS_SUCCESS) {
        pi_destroy_config(p4info_tmp);
        RETURN_ERROR_STATUS(Code::UNKNOWN,
                            "Error in first phase of device update");
      }
      p4_change(config.p4info(), p4info_tmp);
    }

    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT ||
        a == p4::SetForwardingPipelineConfigRequest_Action_COMMIT) {
      pi_status = pi_update_device_end(device_id);
      if (pi_status != PI_STATUS_SUCCESS) {
        RETURN_ERROR_STATUS(Code::UNKNOWN,
                            "Error in second phase of device update");
      }
    }

    RETURN_OK_STATUS();
  }

  Status pipeline_config_get(p4::ForwardingPipelineConfig *config) {
    config->set_device_id(device_id);
    config->mutable_p4info()->CopyFrom(p4info_proto);
    // TODO(antonin): we do not set the p4_device_config bytes field, as we do
    // not have a local copy of it; if it is needed by the controller, we will
    // find a way to return it as well.
    RETURN_OK_STATUS();
  }

  Status write(const p4::WriteRequest &request) {
    Status status;
    status.set_code(Code::OK);
    SessionTemp session(true  /* = batch */);
    for (const auto &update : request.updates()) {
      const auto &entity = update.entity();
      switch (entity.entity_case()) {
        case p4::Entity::kExternEntry:
          Logger::get()->error("No extern support yet");
          status.set_code(Code::UNIMPLEMENTED);
          break;
        case p4::Entity::kTableEntry:
          status = table_write(update.type(), entity.table_entry(), session);
          break;
        case p4::Entity::kActionProfileMember:
          status = action_profile_member_write(
              update.type(), entity.action_profile_member(), session);
          break;
        case p4::Entity::kActionProfileGroup:
          status = action_profile_group_write(
              update.type(), entity.action_profile_group(), session);
          break;
        case p4::Entity::kMeterEntry:
          status = meter_write(update.type(), entity.meter_entry(), session);
          break;
        case p4::Entity::kDirectMeterEntry:
          status = direct_meter_write(
              update.type(), entity.direct_meter_entry(), session);
          break;
        case p4::Entity::kCounterEntry:
          status = ERROR_STATUS(Code::UNIMPLEMENTED,
                                "Writing to counters is not supported yet");
          break;
        case p4::Entity::kDirectCounterEntry:
          status = ERROR_STATUS(
              Code::UNIMPLEMENTED,
              "Writing to direct counters is not supported yet");
          break;
        default:
          status = ERROR_STATUS(Code::UNKNOWN, "Incorrect entity type");
          break;
      }
      if (status.code() != Code::OK) break;
    }
    return status;
  }

  Status read(const p4::ReadRequest &request,
              p4::ReadResponse *response) const {
    Status status;
    status.set_code(Code::OK);
    for (const auto &entity : request.entities()) {
      status = read_one(entity, response);
      if (status.code() != Code::OK) break;
    }
    return status;
  }

  Status read_one(const p4::Entity &entity, p4::ReadResponse *response) const {
    Status status;
    SessionTemp session(false  /* = batch */);
    switch (entity.entity_case()) {
      case p4::Entity::kTableEntry:
        status = table_read(entity.table_entry(), session, response);
        break;
      case p4::Entity::kActionProfileMember:
        status = action_profile_member_read(
            entity.action_profile_member(), session, response);
        break;
      case p4::Entity::kActionProfileGroup:
        status = action_profile_group_read(
            entity.action_profile_group(), session, response);
        break;
      case p4::Entity::kMeterEntry:
        status = ERROR_STATUS(Code::UNIMPLEMENTED,
                              "Reading meter spec is not supported yet");
        break;
      case p4::Entity::kDirectMeterEntry:
        status = ERROR_STATUS(Code::UNIMPLEMENTED,
                              "Reading direct meter spec is not supported yet");
        break;
      case p4::Entity::kCounterEntry:
        status = counter_read(entity.counter_entry(), session, response);
        break;
      case p4::Entity::kDirectCounterEntry:
        status = direct_counter_read(
            entity.direct_counter_entry(), session, response);
        break;
      default:
        status = ERROR_STATUS(Code::UNKNOWN, "Incorrect entity type");
        break;
    }
    return status;
  }

  Status table_write(p4::Update_Type update, const p4::TableEntry &table_entry,
                     const SessionTemp &session) {
    if (!check_p4_id(table_entry.table_id(), P4ResourceType::TABLE))
      return make_invalid_p4_id_status();
    if (table_entry.has_meter_config() || table_entry.has_counter_data()) {
      RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
                          "Direct resources not supported in TableEntry yet");
    }
    Status status;
    switch (update) {
      case p4::Update_Type_UNSPECIFIED:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
      case p4::Update_Type_INSERT:
        return table_insert(table_entry, session);
      case p4::Update_Type_MODIFY:
        return table_modify(table_entry, session);
      case p4::Update_Type_DELETE:
        return table_delete(table_entry, session);
      default:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
    }
    return status;
  }

  Status meter_write(p4::Update_Type update, const p4::MeterEntry &meter_entry,
                     const SessionTemp &session) {
    if (!check_p4_id(meter_entry.meter_id(), P4ResourceType::METER))
      return make_invalid_p4_id_status();
    switch (update) {
      case p4::Update_Type_UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT);
      case p4::Update_Type_INSERT:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "INSERT update type not supported for meters");
      case p4::Update_Type_MODIFY:
        {
          auto pi_meter_spec = meter_spec_proto_to_pi(meter_entry.config());
          auto pi_status = pi_meter_set(session.get(), device_tgt,
                                        meter_entry.meter_id(),
                                        meter_entry.index(),
                                        &pi_meter_spec);
          if (pi_status != PI_STATUS_SUCCESS)
            RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when writing meter spec");
        }
        break;
      case p4::Update_Type_DELETE:  // TODO(antonin): return error instead?
        {
          pi_meter_spec_t pi_meter_spec =
              {0, 0, 0, 0, PI_METER_UNIT_DEFAULT, PI_METER_TYPE_DEFAULT};
          auto pi_status = pi_meter_set(session.get(), device_tgt,
                                        meter_entry.meter_id(),
                                        meter_entry.index(),
                                        &pi_meter_spec);
          if (pi_status != PI_STATUS_SUCCESS)
            RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when writing meter spec");
        }
        break;
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT);
    }
    RETURN_OK_STATUS();
  }

  Status entry_handle_from_table_entry(const p4::TableEntry &table_entry,
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

  Status direct_meter_write(p4::Update_Type update,
                            const p4::DirectMeterEntry &meter_entry,
                            const SessionTemp &session) {
    if (!check_p4_id(meter_entry.meter_id(), P4ResourceType::METER))
      return make_invalid_p4_id_status();

    const auto &table_entry = meter_entry.table_entry();
    auto table_lock = table_info_store.lock_table(table_entry.table_id());

    pi_entry_handle_t entry_handle = 0;
    {
      auto status = entry_handle_from_table_entry(table_entry, &entry_handle);
      if (IS_ERROR(status)) return status;
    }

    switch (update) {
      case p4::Update_Type_UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT);
      case p4::Update_Type_INSERT:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                            "INSERT update type not supported for meters");
      case p4::Update_Type_MODIFY:
        {
          auto pi_meter_spec = meter_spec_proto_to_pi(meter_entry.config());
          auto pi_status = pi_meter_set_direct(session.get(), device_tgt,
                                               meter_entry.meter_id(),
                                               entry_handle,
                                               &pi_meter_spec);
          if (pi_status != PI_STATUS_SUCCESS) {
            RETURN_ERROR_STATUS(Code::UNKNOWN,
                                "Error when writing direct meter spec");
          }
        }
        break;
      case p4::Update_Type_DELETE:  // TODO(antonin): return error instead?
        {
          pi_meter_spec_t pi_meter_spec =
              {0, 0, 0, 0, PI_METER_UNIT_DEFAULT, PI_METER_TYPE_DEFAULT};
          auto pi_status = pi_meter_set_direct(session.get(), device_tgt,
                                               meter_entry.meter_id(),
                                               entry_handle,
                                               &pi_meter_spec);
          if (pi_status != PI_STATUS_SUCCESS) {
            RETURN_ERROR_STATUS(Code::UNKNOWN,
                                "Error when writing direct meter spec");
          }
        }
        break;
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT);
    }
    RETURN_OK_STATUS();
  }

  Code parse_match_key(p4_id_t table_id, const pi_match_key_t *match_key,
                       p4::TableEntry *entry) const {
    auto num_match_fields = pi_p4info_table_num_match_fields(
        p4info.get(), table_id);
    MatchKeyReader mk_reader(match_key);
    auto priority = mk_reader.get_priority();
    if (priority > 0) entry->set_priority(priority);
    for (size_t j = 0; j < num_match_fields; j++) {
      auto finfo = pi_p4info_table_match_field_info(p4info.get(), table_id, j);
      auto mf = entry->add_match();
      mf->set_field_id(finfo->mf_id);
      switch (finfo->match_type) {
        case PI_P4INFO_MATCH_TYPE_VALID:
          {
            auto valid = mf->mutable_valid();
            bool value;
            mk_reader.get_valid(finfo->mf_id, &value);
            valid->set_value(value);
          }
          break;
        case PI_P4INFO_MATCH_TYPE_EXACT:
          {
            auto exact = mf->mutable_exact();
            mk_reader.get_exact(finfo->mf_id, exact->mutable_value());
          }
          break;
        case PI_P4INFO_MATCH_TYPE_LPM:
          {
            auto lpm = mf->mutable_lpm();
            int pLen;
            mk_reader.get_lpm(finfo->mf_id, lpm->mutable_value(), &pLen);
            lpm->set_prefix_len(pLen);
          }
          break;
        case PI_P4INFO_MATCH_TYPE_TERNARY:
          {
            auto ternary = mf->mutable_ternary();
            mk_reader.get_ternary(finfo->mf_id, ternary->mutable_value(),
                                  ternary->mutable_mask());
          }
          break;
        case PI_P4INFO_MATCH_TYPE_RANGE:
          {
            auto range = mf->mutable_range();
            mk_reader.get_range(finfo->mf_id, range->mutable_low(),
                                range->mutable_high());
          }
          break;
        default:
          return Code::UNKNOWN;
      }
    }
    return Code::OK;
  }

  Code parse_action_data(const pi_action_data_t *pi_action_data,
                         p4::Action *action) const {
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
    return Code::OK;
  }

  Code parse_action_entry(p4_id_t table_id, const pi_table_entry_t *pi_entry,
                          p4::TableEntry *entry) const {
    if (pi_entry->entry_type == PI_ACTION_ENTRY_TYPE_NONE) return Code::OK;

    auto table_action = entry->mutable_action();
    if (pi_entry->entry_type == PI_ACTION_ENTRY_TYPE_INDIRECT) {
      auto indirect_h = pi_entry->entry.indirect_handle;
      auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                               table_id);
      // check that table is indirect
      if (action_prof_id == PI_INVALID_ID) return Code::UNKNOWN;
      auto action_prof_mgr = get_action_prof_mgr(action_prof_id);
      auto member_id = action_prof_mgr->retrieve_member_id(indirect_h);
      if (member_id != nullptr) {
        table_action->set_action_profile_member_id(*member_id);
        return Code::OK;
      }
      auto group_id = action_prof_mgr->retrieve_group_id(indirect_h);
      if (group_id == nullptr) return Code::UNKNOWN;
      table_action->set_action_profile_group_id(*group_id);
      return Code::OK;
    }

    return parse_action_data(pi_entry->entry.action_data,
                             table_action->mutable_action());
  }

  // An is a functor which will be called on entries and needs to append a new
  // p4::TableEntry to entries and return a pointer to it
  template <typename T, typename Accessor>
  Status table_read_common(p4_id_t table_id, const SessionTemp &session,
                           T *entries, Accessor An) const {
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
    Code code = Code::OK;
    pi::MatchKey mk(p4info.get(), table_id);
    for (size_t i = 0; i < num_entries; i++) {
      pi_table_entries_next(res, &entry, &entry_handle);
      auto table_entry = An(entries);
      table_entry->set_table_id(table_id);
      code = parse_match_key(table_id, entry.match_key, table_entry);
      if (code != Code::OK) break;
      code = parse_action_entry(table_id, &entry.entry, table_entry);
      if (code != Code::OK) break;
      // TODO(antonin): what I really want to do here is a heterogeneous lookup;
      // instead I make a copy of the match key in the right format and I use
      // this for the lookup. If this is a performance issue, we can find a
      // better solution.
      mk.from(entry.match_key);
      auto entry_data = table_info_store.get_entry(table_id, mk);
      // this would point to a serious bug in the implementation, and shoudn't
      // occur given that we keep the local state in sync with lower level state
      // thanks to our per-table lock.
      if (entry_data == nullptr) {
        Logger::get()->critical("Table state out-of-sync with target");
        assert(0 && "Invalid state");
      }
      table_entry->set_controller_metadata(entry_data->controller_metadata);
    }

    pi_table_entries_fetch_done(session.get(), res);

    RETURN_STATUS(code);
  }

  Status table_read_one(p4_id_t table_id, const SessionTemp &session,
                        p4::ReadResponse *response) const {
    return table_read_common(
        table_id, session, response,
        [] (decltype(response) r) {
          return r->add_entities()->mutable_table_entry(); });
  }

  // TODO(antonin): full filtering on the match key, action, ...
  // TODO(antonin): direct resources
  Status table_read(const p4::TableEntry &table_entry,
                    const SessionTemp &session,
                    p4::ReadResponse *response) const {
    if (table_entry.table_id() == 0) {  // read all entries for all tables
      for (auto t_id = pi_p4info_table_begin(p4info.get());
           t_id != pi_p4info_table_end(p4info.get());
           t_id = pi_p4info_table_next(p4info.get(), t_id)) {
        auto status = table_read_one(t_id, session, response);
        if (IS_ERROR(status)) return status;
      }
    } else {  // read for a single table
      if (!check_p4_id(table_entry.table_id(), P4ResourceType::TABLE))
        return make_invalid_p4_id_status();
      auto status = table_read_one(table_entry.table_id(), session, response);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status action_profile_member_write(p4::Update_Type update,
                                     const p4::ActionProfileMember &member,
                                     const SessionTemp &session) {
    if (!check_p4_id(member.action_profile_id(),
                     P4ResourceType::ACTION_PROFILE))
      return make_invalid_p4_id_status();
    auto action_prof_mgr = get_action_prof_mgr(member.action_profile_id());
    if (action_prof_mgr == nullptr) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Not a valid action profile id: {}",
                          member.action_profile_id());
    }
    switch (update) {
      case p4::Update_Type_UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT);
      case p4::Update_Type_INSERT:
        return action_prof_mgr->member_create(member, session);
      case p4::Update_Type_MODIFY:
        return action_prof_mgr->member_modify(member, session);
      case p4::Update_Type_DELETE:
        return action_prof_mgr->member_delete(member, session);
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT);
    }
    assert(0);
    RETURN_ERROR_STATUS(Code::UNKNOWN);  // UNREACHABLE
  }

  Status action_profile_group_write(p4::Update_Type update,
                                    const p4::ActionProfileGroup &group,
                                    const SessionTemp &session) {
    if (!check_p4_id(group.action_profile_id(), P4ResourceType::ACTION_PROFILE))
      return make_invalid_p4_id_status();
    auto action_prof_mgr = get_action_prof_mgr(group.action_profile_id());
    if (action_prof_mgr == nullptr) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Not a valid action profile id: {}",
                          group.action_profile_id());
    }
    switch (update) {
      case p4::Update_Type_UNSPECIFIED:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT);
      case p4::Update_Type_INSERT:
        return action_prof_mgr->group_create(group, session);
      case p4::Update_Type_MODIFY:
        return action_prof_mgr->group_modify(group, session);
      case p4::Update_Type_DELETE:
        return action_prof_mgr->group_delete(group, session);
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT);
    }
    assert(0);
    RETURN_ERROR_STATUS(Code::UNKNOWN);  // UNREACHABLE
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
      code = parse_action_data(action_data, member->mutable_action());
      if (code != Code::OK) break;
      auto member_id = action_prof_mgr->retrieve_member_id(member_h);
      if (member_id == nullptr) {
        Logger::get()->critical("Cannot map member handle to member id");
        code = Code::UNKNOWN;
        break;
      }
      member->set_member_id(*member_id);
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
      auto group_id = action_prof_mgr->retrieve_group_id(group_h);
      if (group_id == nullptr) {
        Logger::get()->critical("Cannot map group handle to group id");
        code = Code::UNKNOWN;
        break;
      }
      auto group_type = action_prof_mgr->retrieve_group_type(*group_id);
      group->set_group_id(*group_id);
      group->set_type(group_type);
      for (size_t j = 0; j < num; j++) {
        auto member_id = action_prof_mgr->retrieve_member_id(members_h[j]);
        if (member_id == nullptr) {
          Logger::get()->critical("Cannot map member handle to member id");
          code = Code::UNKNOWN;
          break;
        }
        auto member = group->add_members();
        member->set_member_id(*member_id);
      }
    }

    pi_act_prof_entries_fetch_done(session.get(), res);

    RETURN_STATUS(code);
  }

  Status action_profile_member_read_one(p4_id_t action_profile_id,
                                        const SessionTemp &session,
                                        p4::ReadResponse *response) const {
    return action_profile_read_common(
        action_profile_id, session, response,
        [] (decltype(response) r) {
          return r->add_entities()->mutable_action_profile_member(); },
        [] (decltype(response)) -> p4::ActionProfileGroup * {
          return nullptr; });
  }

  // TODO(antonin): full filtering
  Status action_profile_member_read(const p4::ActionProfileMember &member,
                                    const SessionTemp &session,
                                    p4::ReadResponse *response) const {
    if (member.action_profile_id() == 0) {
      for (auto act_prof_id = pi_p4info_act_prof_begin(p4info.get());
           act_prof_id != pi_p4info_act_prof_end(p4info.get());
           act_prof_id = pi_p4info_act_prof_next(p4info.get(), act_prof_id)) {
        auto status = action_profile_member_read_one(
            act_prof_id, session, response);
        if (IS_ERROR(status)) return status;
      }
    } else {
      if (!check_p4_id(member.action_profile_id(),
                       P4ResourceType::ACTION_PROFILE))
        return make_invalid_p4_id_status();
      auto status = action_profile_member_read_one(
          member.action_profile_id(), session, response);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status action_profile_group_read_one(p4_id_t action_profile_id,
                                       const SessionTemp &session,
                                       p4::ReadResponse *response) const {
    return action_profile_read_common(
        action_profile_id, session, response,
        [] (decltype(response)) -> p4::ActionProfileMember * {
          return nullptr; },
        [] (decltype(response) r) {
          return r->add_entities()->mutable_action_profile_group(); });
  }

  // TODO(antonin): full filtering
  Status action_profile_group_read(const p4::ActionProfileGroup &group,
                                   const SessionTemp &session,
                                   p4::ReadResponse *response) const {
    if (group.action_profile_id() == 0) {
      for (auto act_prof_id = pi_p4info_act_prof_begin(p4info.get());
           act_prof_id != pi_p4info_act_prof_end(p4info.get());
           act_prof_id = pi_p4info_act_prof_next(p4info.get(), act_prof_id)) {
        auto status = action_profile_group_read_one(
            act_prof_id, session, response);
        if (IS_ERROR(status)) return status;
      }
    } else {
      if (!check_p4_id(group.action_profile_id(),
                       P4ResourceType::ACTION_PROFILE))
        return make_invalid_p4_id_status();
      auto status = action_profile_group_read_one(
          group.action_profile_id(), session, response);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status packet_out_send(const p4::PacketOut &packet) const {
    return packet_io.packet_out_send(packet);
  }

  void packet_in_register_cb(PacketInCb cb, void *cookie) {
    packet_io.packet_in_register_cb(std::move(cb), cookie);
  }

  Status counter_read_one(p4_id_t counter_id,
                          const p4::CounterEntry &counter_entry,
                          const SessionTemp &session,
                          p4::ReadResponse *response) const {
    assert(pi_p4info_counter_get_direct(p4info.get(), counter_id) ==
           PI_INVALID_ID);
    if (counter_entry.index() != 0) {
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
      entry->set_index(index);
      auto status = counter_read_one_index(session, counter_id, entry);
      if (IS_ERROR(status)) return status;
    }
    RETURN_OK_STATUS();
  }

  Status counter_read(const p4::CounterEntry &counter_entry,
                      const SessionTemp &session,
                      p4::ReadResponse *response) const {
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
      if (!check_p4_id(counter_id, P4ResourceType::COUNTER))
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

  Status direct_counter_read_one(p4_id_t counter_id,
                                 const p4::DirectCounterEntry &counter_entry,
                                 const SessionTemp &session,
                                 p4::ReadResponse *response) const {
    assert(pi_p4info_counter_get_direct(p4info.get(), counter_id) !=
           PI_INVALID_ID);

    if (counter_entry.has_table_entry()) {
      const auto &table_entry = counter_entry.table_entry();
      auto table_lock = table_info_store.lock_table(table_entry.table_id());

      pi_entry_handle_t entry_handle = 0;
      {
        auto status = entry_handle_from_table_entry(table_entry, &entry_handle);
        if (IS_ERROR(status)) return status;
      }
      pi_counter_data_t counter_data;
      auto pi_status = pi_counter_read_direct(
          session.get(), device_tgt, counter_id, entry_handle,
          PI_COUNTER_FLAGS_HW_SYNC, &counter_data);
      if (pi_status != PI_STATUS_SUCCESS) {
        RETURN_ERROR_STATUS(Code::UNKNOWN,
                            "Error when reading counter from target");
      }
      auto entry = response->add_entities()->mutable_direct_counter_entry();
      entry->CopyFrom(counter_entry);
      convert_counter_data(counter_data, entry->mutable_data());
      RETURN_OK_STATUS();
    }
    // read all direct counters in table
    RETURN_ERROR_STATUS(
        Code::UNIMPLEMENTED,
        "Reading ALL direct counters in a table is not supported yet");
  }

  Status direct_counter_read(const p4::DirectCounterEntry &counter_entry,
                             const SessionTemp &session,
                             p4::ReadResponse *response) const {
    auto counter_id = counter_entry.counter_id();
    if (counter_id == 0 && counter_entry.has_table_entry()) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "When reading direct counters, you cannot use a counter_id of zero "
          "with a non-empty table_entry");
    }
    if (counter_id == 0) {
      RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
                          "Reading ALL direct counters is not supported yet");
    }
    if (!check_p4_id(counter_id, P4ResourceType::COUNTER))
      return make_invalid_p4_id_status();
    if (pi_p4info_counter_get_direct(p4info.get(), counter_id) ==
        PI_INVALID_ID) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Cannot use DirectCounterEntry with a indirect counter");
    }
    return direct_counter_read_one(
        counter_id, counter_entry, session, response);
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
  bool check_p4_id(p4_id_t p4_id, P4ResourceType expected_type) const {
    return (pi::proto::util::resource_type_from_id(p4_id) == expected_type)
        && pi_p4info_is_valid_id(p4info.get(), p4_id);
  }

  const p4::FieldMatch *find_mf(const p4::TableEntry &entry,
                                pi_p4_id_t mf_id) const {
    for (const auto &mf : entry.match())
      if (mf.field_id() == mf_id) return &mf;
    return nullptr;
  }

  Status validate_match_key(const p4::TableEntry &entry) const {
    auto t_id = entry.table_id();
    size_t num_match_fields;
    auto expected_mf_ids = pi_p4info_table_get_match_fields(
        p4info.get(), t_id, &num_match_fields);
    if (static_cast<size_t>(entry.match().size()) > num_match_fields) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Too many fields in match key");
    }

    Code code = Code::OK;
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
        case PI_P4INFO_MATCH_TYPE_VALID:
          if (!mf->has_valid())
            RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match type");
          break;
        case PI_P4INFO_MATCH_TYPE_EXACT:
          if (!mf->has_exact())
            RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match type");
          code = check_proto_bytestring(mf->exact().value(), bitwidth);
          break;
        case PI_P4INFO_MATCH_TYPE_LPM:
          if (!mf->has_lpm())
            RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match type");
          code = check_proto_bytestring(mf->lpm().value(), bitwidth);
          break;
        case PI_P4INFO_MATCH_TYPE_TERNARY:
          if (!mf->has_ternary())
            RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match type");
          code = check_proto_bytestring(mf->ternary().value(), bitwidth);
          if (code != Code::OK) break;
          code = check_proto_bytestring(mf->ternary().mask(), bitwidth);
          break;
        case PI_P4INFO_MATCH_TYPE_RANGE:
          if (!mf->has_range())
            RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match type");
          code = check_proto_bytestring(mf->range().low(), bitwidth);
          if (code != Code::OK) break;
          code = check_proto_bytestring(mf->range().high(), bitwidth);
          break;
        default:
          assert(0);
          break;
      }
      if (code != Code::OK)
        RETURN_ERROR_STATUS(code, "Invalid bytestring format");
    }
    if (num_mf_matched != entry.match().size())
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Unknown field in match key");
    RETURN_OK_STATUS();
  }

  Status construct_match_key(const p4::TableEntry &entry,
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
      RETURN_OK_STATUS();
    }
    auto status = validate_match_key(entry);
    if (IS_ERROR(status)) return status;
    auto t_id = entry.table_id();
    size_t num_match_fields;
    auto expected_mf_ids = pi_p4info_table_get_match_fields(
        p4info.get(), t_id, &num_match_fields);
    // same as for validate_match_key above: refactor if double loop too
    // expensive
    for (size_t i = 0; i < num_match_fields; i++) {
      auto mf_id = expected_mf_ids[i];
      auto mf_info = pi_p4info_table_match_field_info(p4info.get(), t_id, i);
      auto mf = find_mf(entry, mf_id);
      if (mf != nullptr) {
        switch (mf_info->match_type) {
          case PI_P4INFO_MATCH_TYPE_VALID:
            match_key->set_valid(mf_id, mf->valid().value());
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
    match_key->set_priority(entry.priority());
    RETURN_OK_STATUS();
  }

  Status construct_action_data(uint32_t table_id, const p4::Action &action,
                               pi::ActionEntry *action_entry) const {
    auto action_id = action.action_id();
    if (!check_p4_id(action_id, P4ResourceType::ACTION))
      return make_invalid_p4_id_status();
    if (!pi_p4info_table_is_action_of(p4info.get(), table_id, action_id))
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid action for table");
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
                                         const p4::TableAction &table_action,
                                         pi::ActionEntry *action_entry) {
    auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                             table_id);
    // check that table is indirect
    if (action_prof_id == PI_INVALID_ID) {
      RETURN_ERROR_STATUS(
          Code::INVALID_ARGUMENT,
          "Expected indirect table but table {} is not", table_id);
    }
    auto action_prof_mgr = get_action_prof_mgr(action_prof_id);
    // cannot assert because the action prof id is provided by the PI
    assert(action_prof_mgr);
    const pi_indirect_handle_t *indirect_h = nullptr;
    switch (table_action.type_case()) {
      case p4::TableAction::kActionProfileMemberId:
        indirect_h = action_prof_mgr->retrieve_member_handle(
            table_action.action_profile_member_id());
        break;
      case p4::TableAction::kActionProfileGroupId:
        indirect_h = action_prof_mgr->retrieve_group_handle(
            table_action.action_profile_group_id());
        break;
      default:
        assert(0);
    }
    // invalid member/group id
    if (indirect_h == nullptr)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid member / group id");
    action_entry->init_indirect_handle(*indirect_h);
    RETURN_OK_STATUS();
  }

  // the table_id is needed for indirect entries
  Status construct_action_entry(uint32_t table_id,
                                const p4::TableAction &table_action,
                                pi::ActionEntry *action_entry) {
    switch (table_action.type_case()) {
      case p4::TableAction::kAction:
        return construct_action_data(table_id, table_action.action(),
                                     action_entry);
      case p4::TableAction::kActionProfileMemberId:
      case p4::TableAction::kActionProfileGroupId:
        return construct_action_entry_indirect(table_id, table_action,
                                               action_entry);
      default:
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT);
    }
  }

  Status table_insert(const p4::TableEntry &table_entry,
                      const SessionTemp &session) {
    const auto table_id = table_entry.table_id();
    pi::MatchKey match_key(p4info.get(), table_id);
    {
      auto status = construct_match_key(table_entry, &match_key);
      if (IS_ERROR(status))
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match key");
    }

    pi::ActionEntry action_entry;
    {
      auto status = construct_action_entry(
          table_id, table_entry.action(), &action_entry);
      if (IS_ERROR(status)) return status;
    }

    auto table_lock = table_info_store.lock_table(table_id);

    pi::MatchTable mt(session.get(), device_tgt, p4info.get(), table_id);
    pi_status_t pi_status;
    pi_entry_handle_t handle;
    if (table_entry.is_default_action()) {
      pi_status = mt.default_entry_set(action_entry);
    } else {
      pi_status = mt.entry_add(match_key, action_entry, false, &handle);
      // handle is not used as this frontend do all operations using match key
      (void) handle;
    }
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when adding match entry to target");
    }

    table_info_store.add_entry(
        table_id, match_key,
        TableInfoStore::Data(handle, table_entry.controller_metadata()));

    RETURN_OK_STATUS();
  }

  Status table_modify(const p4::TableEntry &table_entry,
                      const SessionTemp &session) {
    const auto table_id = table_entry.table_id();
    pi::MatchKey match_key(p4info.get(), table_id);
    {
      auto status = construct_match_key(table_entry, &match_key);
      if (IS_ERROR(status))
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match key");
    }

    pi::ActionEntry action_entry;
    {
      auto status = construct_action_entry(
          table_id, table_entry.action(), &action_entry);
      if (IS_ERROR(status)) return status;
    }

    auto table_lock = table_info_store.lock_table(table_id);

    // we need this pointer to update the controller metadata if the modify
    // operation is successful
    auto entry_data = table_info_store.get_entry(table_id, match_key);
    if (entry_data == nullptr)
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Cannot find match entry");

    pi::MatchTable mt(session.get(), device_tgt, p4info.get(), table_id);
    pi_status_t pi_status;
    if (table_entry.is_default_action()) {
      pi_status = mt.default_entry_set(action_entry);
    } else {
      pi_status = mt.entry_modify_wkey(match_key, action_entry);
    }
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when modifying match entry in target");
    }

    entry_data->controller_metadata = table_entry.controller_metadata();

    RETURN_OK_STATUS();
  }

  Status table_delete(const p4::TableEntry &table_entry,
                      const SessionTemp &session) {
    const auto table_id = table_entry.table_id();
    pi::MatchKey match_key(p4info.get(), table_id);
    {
      auto status = construct_match_key(table_entry, &match_key);
      if (IS_ERROR(status))
        RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid match key");
    }

    auto table_lock = table_info_store.lock_table(table_id);

    pi::MatchTable mt(session.get(), device_tgt, p4info.get(), table_id);
    pi_status_t pi_status;
    if (table_entry.is_default_action()) {
      // we do not yet have the ability to clear a default entry, which is not a
      // very interesting feature anyway
      RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
                          "Resetting default entry not supported yet");
    } else {
      pi_status = mt.entry_delete_wkey(match_key);
    }
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when deleting match entry in target");
    }

    table_info_store.remove_entry(table_id, match_key);

    RETURN_OK_STATUS();
  }

  ActionProfMgr *get_action_prof_mgr(uint32_t id) const {
    auto it = action_profs.find(id);
    return (it == action_profs.end()) ? nullptr : it->second.get();
  }

  void convert_counter_data(const pi_counter_data_t &pi_data,
                            p4::CounterData *data) const {
    if (pi_data.valid & PI_COUNTER_UNIT_PACKETS)
      data->set_packet_count(pi_data.packets);
    if (pi_data.valid & PI_COUNTER_UNIT_BYTES)
      data->set_byte_count(pi_data.bytes);
  }

  Status counter_read_one_index(const SessionTemp &session, uint32_t counter_id,
                                p4::CounterEntry *entry,
                                bool hw_sync = false) const {
    auto index = entry->index();
    int flags = hw_sync ? PI_COUNTER_FLAGS_HW_SYNC : PI_COUNTER_FLAGS_NONE;
    pi_counter_data_t counter_data;
    pi_status_t pi_status = pi_counter_read(session.get(), device_tgt,
                                            counter_id, index, flags,
                                            &counter_data);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(Code::UNKNOWN,
                          "Error when reading counter from target");
    }
    convert_counter_data(counter_data, entry->mutable_data());
    RETURN_OK_STATUS();
  }

  device_id_t device_id;
  // for now, we assume all possible pipes of device are programmed in the same
  // way
  pi_dev_tgt_t device_tgt;
  p4::config::P4Info p4info_proto{};
  P4InfoWrapper p4info{nullptr, p4info_deleter};

  PacketIOMgr packet_io;

  // ActionProfMgr is not movable because of mutex
  std::unordered_map<pi_p4_id_t, std::unique_ptr<ActionProfMgr> >
  action_profs{};

  TableInfoStore table_info_store;
};

DeviceMgr::DeviceMgr(device_id_t device_id) {
  pimp = std::unique_ptr<DeviceMgrImp>(new DeviceMgrImp(device_id));
}

DeviceMgr::~DeviceMgr() { }

// PIMPL forwarding

Status
DeviceMgr::pipeline_config_set(
    p4::SetForwardingPipelineConfigRequest_Action action,
    const p4::ForwardingPipelineConfig &config) {
  return pimp->pipeline_config_set(action, config);
}

Status
DeviceMgr::pipeline_config_get(p4::ForwardingPipelineConfig *config) {
  return pimp->pipeline_config_get(config);
}

Status
DeviceMgr::write(const p4::WriteRequest &request) {
  return pimp->write(request);
}

Status
DeviceMgr::read(const p4::ReadRequest &request,
                p4::ReadResponse *response) const {
  return pimp->read(request, response);
}

Status
DeviceMgr::read_one(const p4::Entity &entity,
                    p4::ReadResponse *response) const {
  return pimp->read_one(entity, response);
}

Status
DeviceMgr::packet_out_send(const p4::PacketOut &packet) const {
  return pimp->packet_out_send(packet);
}

void
DeviceMgr::packet_in_register_cb(PacketInCb cb, void *cookie) {
  return pimp->packet_in_register_cb(cb, cookie);
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
