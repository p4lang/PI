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

class DeviceMgrImp {
 public:
  DeviceMgrImp(device_id_t device_id)
      : device_id(device_id) { }

  // TODO(antonin)
  Status table_write(const p4::TableUpdate &table_update) {
    (void) table_update;
    return Status();
  }

  // TODO(antonin)
  Status table_read(p4_id_t table_id,
                    std::vector<p4::TableEntry> *entries) const {
    (void) table_id; (void) entries;
    return Status();
  }

  // TODO(antonin)
  Status action_profile_write(
      const p4::ActionProfileUpdate &action_profile_update) {
    (void) action_profile_update;
    return Status();
  }

  // TODO(antonin)
  Status action_profile_read(
      p4_id_t action_profile_id,
      std::vector<p4::ActionProfileEntry> *entries) const {
    (void) action_profile_id; (void) entries;
    return Status();
  }

  // TODO(antonin)
  Status packet_out_send(const std::string &packet) const {
    (void) packet;
    return Status();
  }

  // TODO(antonin)
  void packet_in_register_cb(PacketInCb cb, void *cookie) {
    (void) cb; (void) cookie;
  }

 private:
  device_id_t device_id;
};

DeviceMgr::DeviceMgr(device_id_t device_id) {
  pimp = std::unique_ptr<DeviceMgrImp>(new DeviceMgrImp(device_id));
}

DeviceMgr::~DeviceMgr() { }

// PIMPL forwarding

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

}  // namespace proto

}  // namespace fe

}  // namespace pi
