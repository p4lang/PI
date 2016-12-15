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

#include <PI/pi.h>
#include <PI/frontends/cpp/tables.h>
#include <PI/frontends/proto/device_mgr.h>

#include <memory>
#include <string>
#include <vector>

#include "google/rpc/code.pb.h"

#include "p4info_to_and_from_proto.h"  // for p4info_proto_reader
#include "action_prof_mgr.h"
#include "common.h"

namespace pi {

namespace fe {

namespace proto {

using device_id_t = DeviceMgr::device_id_t;
using p4_id_t = DeviceMgr::p4_id_t;
using Status = DeviceMgr::Status;
using PacketInCb = DeviceMgr::PacketInCb;
using Code = ::google::rpc::Code;
using common::SessionTemp;

// We don't yet have a mapping from PI error codes to ::google::rpc::Code
// values, so for now we almost always return UNKNOWN. It is likely that we will
// have our own error namespace (in addition to ::google::rpc::Code) anyway.

namespace {

// wraps the p4info pointer provided by the PI library into a unique_ptr
auto p4info_deleter = [](pi_p4info_t *p4info) {
  pi_destroy_config(p4info);
};
using P4InfoWrapper = std::unique_ptr<pi_p4info_t, decltype(p4info_deleter)>;

}  // namespace

class DeviceMgrImp {
 public:
  friend class DeviceMgr::counter_iterator;

  explicit DeviceMgrImp(device_id_t device_id)
      : device_id(device_id),
        device_tgt({static_cast<pi_dev_id_t>(device_id), 0xff}) { }

  ~DeviceMgrImp() {
    pi_remove_device(device_id);
  }

  // we assume that the DeviceMgr client is smart enough here: for p4info
  // updates we do not do any locking; we assume that the client will not issue
  // table commands... while updating p4info
  void p4_change(pi_p4info_t *p4info_new) {
    action_profs.clear();
    for (auto act_prof_id = pi_p4info_act_prof_begin(p4info_new);
         act_prof_id != pi_p4info_act_prof_end(p4info_new);
         act_prof_id = pi_p4info_act_prof_next(p4info_new, act_prof_id)) {
      std::unique_ptr<ActionProfMgr> mgr(
          new ActionProfMgr(device_tgt, act_prof_id, p4info_new));
      action_profs.emplace(act_prof_id, std::move(mgr));
    }

    // we do this last, so that the ActProfMgr instances never point to an
    // invalid p4info, even though this is not strictly required here
    p4info.reset(p4info_new);
  }

  Status init(const p4::config::P4Info &p4info_proto,
              const p4::tmp::DeviceAssignRequest_Extras &extras) {
    Status status;
    pi_status_t pi_status;
    std::vector<pi_assign_extra_t> assign_options;
    for (const auto &p : extras.kv()) {
      pi_assign_extra_t e;
      e.key = p.first.c_str();
      e.v = p.second.c_str();
      e.end_of_extras = 0;
      assign_options.push_back(e);
    }
    assign_options.push_back({1, NULL, NULL});
    pi_p4info_t *p4info_tmp = nullptr;
    if (!pi::p4info::p4info_proto_reader(p4info_proto, &p4info_tmp)) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    p4_change(p4info_tmp);
    pi_status = pi_assign_device(device_id, p4info.get(),
                                 assign_options.data());
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    status.set_code(Code::OK);
    return status;
  }

  Status update_start(const p4::config::P4Info &p4info_proto,
                      const std::string &device_data) {
    Status status;
    pi_status_t pi_status;
    pi_p4info_t *p4info_tmp = nullptr;
    if (!pi::p4info::p4info_proto_reader(p4info_proto, &p4info_tmp)) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    pi_status = pi_update_device_start(device_id, p4info_tmp,
                                       device_data.data(), device_data.size());
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      pi_destroy_config(p4info_tmp);
      return status;
    }
    p4_change(p4info_tmp);
    status.set_code(Code::OK);
    return status;
  }

  Status update_end() {
    Status status;
    auto pi_status = pi_update_device_end(device_id);
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    status.set_code(Code::OK);
    return status;
  }

  Status table_write(const p4::TableUpdate &table_update) {
    Status status;
    switch (table_update.type()) {
      case p4::TableUpdate_Type_UNSPECIFIED:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
      case p4::TableUpdate_Type_INSERT:
        return table_insert(table_update.table_entry());
      case p4::TableUpdate_Type_MODIFY:
        return table_modify(table_update.table_entry());
      case p4::TableUpdate_Type_DELETE:
        return table_delete(table_update.table_entry());
      default:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
    }
    return status;
  }

  // TODO(antonin)
  Status table_read(p4_id_t table_id,
                    std::vector<p4::TableEntry> *entries) const {
    (void) table_id; (void) entries;
    Status status;
    status.set_code(Code::UNIMPLEMENTED);
    return status;
  }

  // TODO(antonin)
  Status action_profile_write(
      const p4::ActionProfileUpdate &action_profile_update) {
    Status status;
    const auto &entry = action_profile_update.action_profile_entry();
    auto update_type = action_profile_update.type();
    switch (update_type) {
      case p4::ActionProfileUpdate_Type_CREATE:
        return action_profile_create(entry);
      case p4::ActionProfileUpdate_Type_MODIFY:
        return action_profile_modify(entry);
      case p4::ActionProfileUpdate_Type_DELETE:
        return action_profile_delete(entry);
      default:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
    }
    return status;
  }

  // TODO(antonin)
  Status action_profile_read(
      p4_id_t action_profile_id,
      std::vector<p4::ActionProfileEntry> *entries) const {
    (void) action_profile_id; (void) entries;
    Status status;
    status.set_code(Code::UNIMPLEMENTED);
    return status;
  }

  Status packet_out_send(const std::string &packet) const {
    Status status;
    auto pi_status = pi_packetout_send(device_id, packet.data(), packet.size());
    if (pi_status != PI_STATUS_SUCCESS)
      status.set_code(Code::UNKNOWN);
    else
      status.set_code(Code::OK);
    return status;
  }

  void packet_in_register_cb(PacketInCb cb, void *cookie) {
    cb_ = std::move(cb);
    cookie_ = cookie;
    pi_packetin_register_cb(device_id, &DeviceMgrImp::packet_in_cb,
                            static_cast<void *>(this));
  }

  // TODO(antonin)
  Status counter_write(const p4::CounterEntry &entry) {
    (void) entry;
    return Status();
  }

  Status counter_read(p4::CounterEntry *entry) const {
    Status status;
    auto counter_id = entry->counter_id();
    auto is_direct = (pi_p4info_counter_get_direct(p4info.get(), counter_id)
                      != PI_INVALID_ID);
    if (is_direct) {  // TODO(antonin)
      status.set_code(Code::UNIMPLEMENTED);
      return status;
    }
    SessionTemp session;
    if (entry->cells().empty()) {
      auto counter_size = pi_p4info_counter_get_size(p4info.get(), counter_id);
      for (size_t index = 0; index < counter_size; index++) {
        auto code = counter_read_one_index(session, counter_id,
                                           entry->add_cells());
        if (code != Code::OK) {
          status.set_code(code);
          return status;
        }
      }
    } else {
      for (auto &cell : *entry->mutable_cells()) {
        auto code = counter_read_one_index(session, counter_id, &cell);
        if (code != Code::OK) {
          status.set_code(code);
          return status;
        }
      }
    }
    status.set_code(Code::OK);
    return status;
  }

  static void init(size_t max_devices) {
    assert(pi_init(max_devices, NULL) == PI_STATUS_SUCCESS);
  }

  static void destroy() {
    pi_destroy();
  }

 private:
  Code construct_match_key(const p4::TableEntry &entry,
                           pi::MatchKey *match_key) const {
    for (const auto &mf : entry.match()) {
      switch (mf.field_match_type_case()) {
        case p4::FieldMatch::kExact:
          match_key->set_exact(mf.field_id(), mf.exact().value().data(),
                               mf.exact().value().size());
          break;
        case p4::FieldMatch::kLpm:
          match_key->set_lpm(mf.field_id(), mf.lpm().value().data(),
                             mf.lpm().value().size(), mf.lpm().prefix_len());
          break;
        case p4::FieldMatch::kTernary:
          if (mf.ternary().value().size() != mf.ternary().mask().size())
            return Code::INVALID_ARGUMENT;
          match_key->set_ternary(mf.field_id(), mf.ternary().value().data(),
                                 mf.ternary().mask().data(),
                                 mf.ternary().value().size());
          break;
        case p4::FieldMatch::kRange:
        case p4::FieldMatch::kValid:
          return Code::UNIMPLEMENTED;
        default:
          return Code::INVALID_ARGUMENT;
      }
    }
    return Code::OK;
  }

  Code construct_action_data(const p4::Action &action,
                             pi::ActionEntry *action_entry) {
    action_entry->init_action_data(p4info.get(), action.action_id());
    auto action_data = action_entry->mutable_action_data();
    for (const auto &p : action.params()) {
      action_data->set_arg(p.param_id(), p.value().data(), p.value().size());
    }
    return Code::OK;
  }

  Code construct_action_entry_indirect(uint32_t table_id,
                                       const p4::TableAction &table_action,
                                       pi::ActionEntry *action_entry) {
    auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                             table_id);
    // check that table is indirect
    if (action_prof_id == PI_INVALID_ID) return Code::INVALID_ARGUMENT;
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
    if (indirect_h == nullptr) return Code::INVALID_ARGUMENT;
    action_entry->init_indirect_handle(*indirect_h);
    return Code::OK;
  }

  // the table_id is needed for indirect entries
  Code construct_action_entry(uint32_t table_id,
                              const p4::TableAction &table_action,
                              pi::ActionEntry *action_entry) {
    switch (table_action.type_case()) {
      case p4::TableAction::kAction:
        return construct_action_data(table_action.action(), action_entry);
      case p4::TableAction::kActionProfileMemberId:
      case p4::TableAction::kActionProfileGroupId:
        return construct_action_entry_indirect(table_id, table_action,
                                               action_entry);
      default:
        return Code::INVALID_ARGUMENT;
    }
  }

  Status table_insert(const p4::TableEntry &table_entry) {
    Status status;
    Code code;
    const auto table_id = table_entry.table_id();
    pi::MatchKey match_key(p4info.get(), table_id);
    code = construct_match_key(table_entry, &match_key);
    if (code != Code::OK) {
      status.set_code(code);
      return status;
    }

    pi::ActionEntry action_entry;
    code = construct_action_entry(
        table_id, table_entry.action(), &action_entry);
    if (code != Code::OK) {
      status.set_code(code);
      return status;
    }

    SessionTemp session;
    pi::MatchTable mt(session.get(), device_tgt, p4info.get(), table_id);
    pi_status_t pi_status;
    // an empty match means default entry
    if (table_entry.match().empty()) {
      pi_status = mt.default_entry_set(action_entry);
    } else {
      pi_entry_handle_t handle;
      pi_status = mt.entry_add(match_key, action_entry, false, &handle);
      // handle is not used as this frontend do all operations using match key
      (void) handle;
    }
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }

    status.set_code(Code::OK);
    return status;
  }

  Status table_modify(const p4::TableEntry &table_entry) {
    (void) table_entry;
    Status status;
    status.set_code(Code::UNIMPLEMENTED);
    return status;
  }

  Status table_delete(const p4::TableEntry &table_entry) {
    Status status;
    Code code;
    const auto table_id = table_entry.table_id();
    pi::MatchKey match_key(p4info.get(), table_id);
    code = construct_match_key(table_entry, &match_key);
    if (code != Code::OK) {
      status.set_code(code);
      return status;
    }

    SessionTemp session;
    pi::MatchTable mt(session.get(), device_tgt, p4info.get(), table_id);
    pi_status_t pi_status;
    // an empty match means default entry
    if (table_entry.match().empty()) {
      // we do not yet have the ability to clear a default entry, which is not a
      // very interesting feature anyway
      status.set_code(Code::UNIMPLEMENTED);
      return status;
    } else {
      pi_status = mt.entry_delete_wkey(match_key);
    }
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }

    status.set_code(Code::OK);
    return status;
  }

  ActionProfMgr *get_action_prof_mgr(uint32_t id) {
    auto it = action_profs.find(id);
    return (it == action_profs.end()) ? nullptr : it->second.get();
  }

  ActionProfMgr *get_action_prof_mgr(const p4::ActionProfileEntry &entry) {
    return get_action_prof_mgr(entry.action_profile_id());
  }

  // this function to avoid code duplication
  // we can probably simplify this code if the action_profile_id is moved up in
  // pi.proto
  template <typename FMember, typename FGroup>
  Status action_profile_common(const p4::ActionProfileEntry &entry,
                               FMember fmember, FGroup fgroup) {
    Status status;
    auto action_prof_mgr = get_action_prof_mgr(entry);
    if (action_prof_mgr == nullptr) {
      status.set_code(Code::INVALID_ARGUMENT);
      return status;
    }
    switch (entry.type_case()) {
      case p4::ActionProfileEntry::kMember:
        return (action_prof_mgr->*fmember)(entry.member());
      case p4::ActionProfileEntry::kGroup:
        return (action_prof_mgr->*fgroup)(entry.group());
      default:  // cannot happen (caught by get_action_prof_mgr)
        assert(0);
    }
  }

  Status action_profile_create(const p4::ActionProfileEntry &entry) {
    return action_profile_common(
        entry, &ActionProfMgr::member_create, &ActionProfMgr::group_create);
  }

  Status action_profile_modify(const p4::ActionProfileEntry &entry) {
    return action_profile_common(
        entry, &ActionProfMgr::member_modify, &ActionProfMgr::group_modify);
  }

  Status action_profile_delete(const p4::ActionProfileEntry &entry) {
    return action_profile_common(
        entry, &ActionProfMgr::member_delete, &ActionProfMgr::group_delete);
  }

  Code counter_read_one_index(const SessionTemp &session, uint32_t counter_id,
                              p4::CounterCell *cell) const {
    auto index = cell->index();
    int flags = PI_COUNTER_FLAGS_NONE;
    pi_counter_data_t counter_data;
    pi_status_t pi_status = pi_counter_read(session.get(), device_tgt,
                                            counter_id, index, flags,
                                            &counter_data);
    if (pi_status != PI_STATUS_SUCCESS) return Code::UNKNOWN;
    auto data = cell->mutable_data();
    if (counter_data.valid & PI_COUNTER_UNIT_PACKETS)
      data->set_packet_count(counter_data.packets);
    if (counter_data.valid & PI_COUNTER_UNIT_BYTES)
      data->set_byte_count(counter_data.bytes);
    return Code::OK;
  }

  static void packet_in_cb(pi_dev_id_t dev_id, const char *pkt, size_t size,
                           void *cookie) {
    auto mgr = static_cast<DeviceMgrImp *>(cookie);
    assert(dev_id == mgr->device_id);
    mgr->cb_(mgr->device_id, std::string(pkt, size), mgr->cookie_);
  }

  device_id_t device_id;
  // for now, we assume all possible pipes of device are programmed in the same
  // way
  pi_dev_tgt_t device_tgt;
  P4InfoWrapper p4info{nullptr, p4info_deleter};

  PacketInCb cb_;
  void *cookie_;

  // ActionProfMgr is not movable because of mutex
  std::unordered_map<pi_p4_id_t, std::unique_ptr<ActionProfMgr> >
  action_profs{};
};

DeviceMgr::DeviceMgr(device_id_t device_id) {
  pimp = std::unique_ptr<DeviceMgrImp>(new DeviceMgrImp(device_id));
}

DeviceMgr::~DeviceMgr() { }

// PIMPL forwarding

Status
DeviceMgr::init(const p4::config::P4Info &p4info,
                const p4::tmp::DeviceAssignRequest_Extras &extras) {
  return pimp->init(p4info, extras);
}

Status
DeviceMgr::update_start(const p4::config::P4Info &p4info,
                        const std::string &device_data) {
  return pimp->update_start(p4info, device_data);
}

Status
DeviceMgr::update_end() {
  return pimp->update_end();
}

Status
DeviceMgr::table_write(const p4::TableUpdate &table_update) {
  return pimp->table_write(table_update);
}

Status
DeviceMgr::table_read(p4_id_t table_id,
                      std::vector<p4::TableEntry> *entries) const {
  return pimp->table_read(table_id, entries);
}

Status
DeviceMgr::action_profile_write(
    const p4::ActionProfileUpdate &action_profile_update) {
  return pimp->action_profile_write(action_profile_update);
}

Status
DeviceMgr::action_profile_read(
    p4_id_t action_profile_id,
    std::vector<p4::ActionProfileEntry> *entries) const {
  return pimp->action_profile_read(action_profile_id, entries);
}

Status
DeviceMgr::packet_out_send(const std::string &packet) const {
  return pimp->packet_out_send(packet);
}

void
DeviceMgr::packet_in_register_cb(PacketInCb cb, void *cookie) {
  return pimp->packet_in_register_cb(cb, cookie);
}

Status
DeviceMgr::counter_write(const p4::CounterEntry &entry) {
  return pimp->counter_write(entry);
}

Status
DeviceMgr::counter_read(p4::CounterEntry *entry) const {
  return pimp->counter_read(entry);
}

void
DeviceMgr::init(size_t max_devices) {
  DeviceMgrImp::init(max_devices);
}

void
DeviceMgr::destroy() {
  DeviceMgrImp::destroy();
}

DeviceMgr::counter_iterator
DeviceMgr::counter_read_begin() const {
  return counter_iterator(pimp.get(), counter_iterator::InitState::BEGIN);
}

DeviceMgr::counter_iterator
DeviceMgr::counter_read_end() const {
  return counter_iterator(pimp.get(), counter_iterator::InitState::END);
}


void
DeviceMgr::counter_iterator::counter_read() {
  auto p4info = device_mgr->p4info.get();
  if (counter_id == pi_p4info_counter_end(p4info)) {
    entry = nullptr;
    return;
  }
  entry->set_counter_id(counter_id);
  entry->clear_cells();
  auto status = device_mgr->counter_read(entry.get());
  assert(status.code() == Code::OK);
}

DeviceMgr::counter_iterator::counter_iterator(const DeviceMgrImp *device_mgr,
                                              InitState init)
    : device_mgr(device_mgr), counter_id(PI_INVALID_ID), entry(nullptr) {
  if (init == InitState::BEGIN) {
    entry = std::make_shared<p4::CounterEntry>();
    auto p4info = device_mgr->p4info.get();
    counter_id = pi_p4info_counter_begin(p4info);
    counter_read();
  }
}

p4::CounterEntry &
DeviceMgr::counter_iterator::operator*() const {
  assert(entry != nullptr && "Invalid iterator dereference.");
  return *entry.get();
}

p4::CounterEntry *
DeviceMgr::counter_iterator::operator->() const {
  assert(entry != nullptr && "Invalid iterator dereference.");
  return entry.get();
}

bool
DeviceMgr::counter_iterator::operator==(const counter_iterator &other) const {
  return (device_mgr == other.device_mgr) && (counter_id == other.counter_id);
}

bool
DeviceMgr::counter_iterator::operator!=(const counter_iterator &other) const {
  return !(*this == other);
}

DeviceMgr::counter_iterator &
DeviceMgr::counter_iterator::operator++() {
  assert(entry != nullptr && "Out-of-bounds iterator increment.");
  auto p4info = device_mgr->p4info.get();
  counter_id = pi_p4info_counter_next(p4info, counter_id);
  counter_read();
  return *this;
}

const DeviceMgr::counter_iterator
DeviceMgr::counter_iterator::operator++(int) {  // NOLINT(readability/function)
  // Use operator++()
  const counter_iterator old(*this);
  ++(*this);
  return old;
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
