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

#include <PI/frontends/proto/device_mgr.h>

#include <PI/pi.h>
#include <PI/frontends/cpp/tables.h>

#include "google/rpc/code.pb.h"

#include <memory>
#include <string>
#include <vector>

namespace pi {

namespace fe {

namespace proto {

using device_id_t = DeviceMgr::device_id_t;
using p4_id_t = DeviceMgr::p4_id_t;
using Status = DeviceMgr::Status;
using PacketInCb = DeviceMgr::PacketInCb;
using Code = ::google::rpc::Code;

// We don't yet have a mapping from PI error codes to ::google::rpc::Code
// values, so for now we almost always return UNKNOWN. It is likely that we will
// have our own error namespace (in addition to ::google::rpc::Code) anyway.

class DeviceMgrImp {
 public:
  DeviceMgrImp(device_id_t device_id)
      : device_id(device_id),
        device_tgt({static_cast<pi_dev_id_t>(device_id), 0xff}) { }

  ~DeviceMgrImp() {
    pi_remove_device(device_id);
    destroy_p4info_if_needed();
  }

  Status init(const std::string &p4info_json,
              const p4tmp::DeviceAssignRequest_Extras &extras) {
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
    pi_status = pi_add_config(p4info_json.c_str(), PI_CONFIG_TYPE_NATIVE_JSON,
                              &p4info);
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    pi_status = pi_assign_device(device_id, p4info, assign_options.data());
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    status.set_code(Code::OK);
    return status;
  }

  Status update_start(const std::string &p4info_json,
                      const std::string &device_data) {
    Status status;
    pi_status_t pi_status;
    pi_p4info_t *p4info_tmp = nullptr;
    pi_status = pi_add_config(p4info_json.c_str(), PI_CONFIG_TYPE_NATIVE_JSON,
                              &p4info_tmp);
    if (pi_status != PI_STATUS_SUCCESS) {
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
    destroy_p4info_if_needed();
    p4info = p4info_tmp;
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
    (void) action_profile_update;
    Status status;
    status.set_code(Code::UNIMPLEMENTED);
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
    if (pi_status != PI_STATUS_SUCCESS) status.set_code(Code::UNKNOWN);
    else status.set_code(Code::OK);
    return status;
  }

  void packet_in_register_cb(PacketInCb cb, void *cookie) {
    cb_ = std::move(cb);
    cookie_ = cookie;
    pi_packetin_register_cb(device_id, &DeviceMgrImp::packet_in_cb,
                            static_cast<void *>(this));
  }

  // TODO(antonin)
  Status counter_write(const p4tmp::CounterEntry &entry) {
    (void) entry;
    return Status();
  }

  Status counter_read(p4_id_t counter_id,
                      p4tmp::CounterReadResponse *rep) const {
    Status status;
    auto is_direct =
        (pi_p4info_counter_get_direct(p4info, counter_id) != PI_INVALID_ID);
    if (is_direct) {
      status.set_code(Code::UNIMPLEMENTED);
      return status;
    }
    auto counter_size = pi_p4info_counter_get_size(p4info, counter_id);
    SessionTemp session;
    pi_status_t pi_status;
    int flags = PI_COUNTER_FLAGS_NONE;
    for (size_t idx = 0; idx < counter_size; idx++) {
      pi_counter_data_t counter_data;
      pi_status = pi_counter_read(session.get(), device_tgt, counter_id,
                                  idx, flags, &counter_data);
      if (pi_status != PI_STATUS_SUCCESS) {
        status.set_code(Code::UNKNOWN);
        return status;
      }
      auto entry = rep->add_entries();
      entry->set_counter_id(counter_id);
      entry->set_index(idx);
      auto data = entry->mutable_data();
      if (counter_data.valid & PI_COUNTER_UNIT_PACKETS) {
        data->set_packets(counter_data.packets);
        data->set_packets_valid(true);
      }
      if (counter_data.valid & PI_COUNTER_UNIT_BYTES) {
        data->set_bytes(counter_data.bytes);
        data->set_bytes_valid(true);
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
  struct SessionTemp {
    SessionTemp() { pi_session_init(&sess); }

    ~SessionTemp() { pi_session_cleanup(sess); }

    pi_session_handle_t get() { return sess; }

    pi_session_handle_t sess;
  };

  void destroy_p4info_if_needed() {
    if (p4info != nullptr) {
      pi_destroy_config(p4info);
      p4info = nullptr;
    }
  }

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
    action_entry->init_action_data(p4info, action.action_id());
    auto action_data = action_entry->mutable_action_data();
    for (const auto &p : action.params()) {
      action_data->set_arg(p.param_id(), p.value().data(), p.value().size());
    }
    return Code::OK;
  }

  Code construct_action_entry(const p4::TableAction &table_action,
                              pi::ActionEntry *action_entry) {
    switch (table_action.type_case()) {
      case p4::TableAction::kAction:
        return construct_action_data(table_action.action(), action_entry);
      case p4::TableAction::kActionProfileMemberId:
        return Code::OK;
      case p4::TableAction::kActionProfileGroupId:
        return Code::OK;
      default:
        return Code::INVALID_ARGUMENT;
    }
  }

  Status table_insert(const p4::TableEntry &table_entry) {
    Status status;
    Code code;
    const auto table_id = table_entry.table_id();
    pi::MatchKey match_key(p4info, table_id);
    code = construct_match_key(table_entry, &match_key);
    if (code != Code::OK) {
      status.set_code(code);
      return status;
    }

    pi::ActionEntry action_entry;
    code = construct_action_entry(table_entry.action(), &action_entry);
    if (code != Code::OK) {
      status.set_code(code);
      return status;
    }

    SessionTemp session;
    pi::MatchTable mt(session.get(), device_tgt, p4info, table_id);
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
    pi::MatchKey match_key(p4info, table_id);
    code = construct_match_key(table_entry, &match_key);
    if (code != Code::OK) {
      status.set_code(code);
      return status;
    }

    SessionTemp session;
    pi::MatchTable mt(session.get(), device_tgt, p4info, table_id);
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
  pi_p4info_t *p4info{nullptr};
  PacketInCb cb_;
  void *cookie_;
};

DeviceMgr::DeviceMgr(device_id_t device_id) {
  pimp = std::unique_ptr<DeviceMgrImp>(new DeviceMgrImp(device_id));
}

DeviceMgr::~DeviceMgr() { }

// PIMPL forwarding

Status
DeviceMgr::init(const std::string &p4info_json,
                const p4tmp::DeviceAssignRequest_Extras &extras) {
  return pimp->init(p4info_json, extras);
}

Status
DeviceMgr::update_start(const std::string &p4info_json,
                        const std::string &device_data) {
  return pimp->update_start(p4info_json, device_data);
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
DeviceMgr::counter_write(const p4tmp::CounterEntry &entry) {
  return pimp->counter_write(entry);
}

Status
DeviceMgr::counter_read(p4_id_t counter_id,
                        p4tmp::CounterReadResponse *entries) const {
  return pimp->counter_read(counter_id, entries);
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
