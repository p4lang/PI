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

#ifndef PROTO_TESTS_MOCK_SWITCH_H_
#define PROTO_TESTS_MOCK_SWITCH_H_

#include <gmock/gmock.h>

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <cstdint>

#include "PI/pi.h"

namespace pi {
namespace proto {
namespace testing {

using device_id_t = uint64_t;

class DummySwitch;

class DummySwitchMock {
 public:
  explicit DummySwitchMock(device_id_t device_id);

  ~DummySwitchMock();

  // used to capture entry handles
  pi_status_t _table_entry_add(pi_p4_id_t table_id,
                               const pi_match_key_t *match_key,
                               const pi_table_entry_t *table_entry,
                               pi_entry_handle_t *h);

  pi_entry_handle_t get_table_entry_handle() const;

  // used to capture handle for members
  pi_status_t _action_prof_member_create(pi_p4_id_t act_prof_id,
                                         const pi_action_data_t *action_data,
                                         pi_indirect_handle_t *h);

  // used to capture handle for groups
  pi_status_t _action_prof_group_create(pi_p4_id_t act_prof_id, size_t max_size,
                                        pi_indirect_handle_t *h);

  pi_indirect_handle_t get_action_prof_handle() const;

  pi_status_t packetin_inject(const std::string &packet) const;

  MOCK_METHOD4(table_entry_add,
               pi_status_t(pi_p4_id_t, const pi_match_key_t *,
                           const pi_table_entry_t *, pi_entry_handle_t *));
  MOCK_METHOD2(table_default_action_set,
               pi_status_t(pi_p4_id_t, const pi_table_entry_t *));
  MOCK_METHOD2(table_default_action_get,
               pi_status_t(pi_p4_id_t, pi_table_entry_t *));
  MOCK_METHOD2(table_entry_delete_wkey,
               pi_status_t(pi_p4_id_t, const pi_match_key_t *));
  MOCK_METHOD3(table_entry_modify_wkey,
               pi_status_t(pi_p4_id_t, const pi_match_key_t *,
                           const pi_table_entry_t *));
  MOCK_METHOD2(table_entries_fetch,
               pi_status_t(pi_p4_id_t, pi_table_fetch_res_t *));

  MOCK_METHOD3(action_prof_member_create,
               pi_status_t(pi_p4_id_t, const pi_action_data_t *,
                           pi_indirect_handle_t *));
  MOCK_METHOD3(action_prof_member_modify,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t,
                           const pi_action_data_t *));
  MOCK_METHOD2(action_prof_member_delete,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t));
  MOCK_METHOD3(action_prof_group_create,
               pi_status_t(pi_p4_id_t, size_t, pi_indirect_handle_t *));
  MOCK_METHOD2(action_prof_group_delete,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t));
  MOCK_METHOD3(action_prof_group_add_member,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t,
                           pi_indirect_handle_t));
  MOCK_METHOD3(action_prof_group_remove_member,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t,
                           pi_indirect_handle_t));
  MOCK_METHOD2(action_prof_entries_fetch,
               pi_status_t(pi_p4_id_t, pi_act_prof_fetch_res_t *));

  MOCK_METHOD3(meter_set,
               pi_status_t(pi_p4_id_t, size_t, const pi_meter_spec_t *));
  MOCK_METHOD3(meter_set_direct,
               pi_status_t(pi_p4_id_t, pi_entry_handle_t,
                           const pi_meter_spec_t *));

  MOCK_METHOD4(counter_read,
               pi_status_t(pi_p4_id_t, size_t, int,
                           pi_counter_data_t *counter_data));
  MOCK_METHOD4(counter_read_direct,
               pi_status_t(pi_p4_id_t, pi_entry_handle_t, int,
                           pi_counter_data_t *counter_data));

  MOCK_METHOD2(packetout_send, pi_status_t(const char *, size_t));

 private:
  std::unique_ptr<DummySwitch> sw;
  pi_indirect_handle_t action_prof_h;
  pi_entry_handle_t table_h;
};

// used to map device ids to DummySwitchMock instances; thread safe in case we
// want to make tests run in parallel
class DeviceResolver {
 public:
  static device_id_t new_switch() {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    assert(r->map.size() < 256);
    for (device_id_t id = 0; id < 256; id++) {
      if (!r->map.count(id)) {
        r->map.emplace(
            id, std::unique_ptr<DummySwitchMock>(new DummySwitchMock(id)));
        return id;
      }
    }
    assert(0);
    return 256;
  }

  static DummySwitchMock *get_switch(device_id_t device_id) {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    return r->map.at(device_id).get();
  }

  static void release_switch(device_id_t device_id) {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    r->map.erase(device_id);
  }

 private:
  static DeviceResolver *get_instance() {
    static DeviceResolver resolver;
    return &resolver;
  }

  mutable std::mutex m{};
  std::map<device_id_t, std::unique_ptr<DummySwitchMock> > map{};
};

class DummySwitchWrapper {
 public:
  DummySwitchWrapper() {
    _device_id = DeviceResolver::new_switch();
    _sw = DeviceResolver::get_switch(_device_id);
  }

  device_id_t device_id() { return _device_id; }

  DummySwitchMock *sw() { return _sw; }

  ~DummySwitchWrapper() {
    DeviceResolver::release_switch(_device_id);
  }

 private:
  device_id_t _device_id{0};
  DummySwitchMock *_sw{nullptr};
};

}  // namespace testing
}  // namespace proto
}  // namespace pi

#endif  // PROTO_TESTS_MOCK_SWITCH_H_
