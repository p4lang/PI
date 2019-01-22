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
#include <vector>

#include <cstdint>

#include "PI/pi.h"
#include "PI/pi_clone.h"
#include "PI/pi_learn.h"
#include "PI/pi_mc.h"

namespace pi {
namespace proto {
namespace testing {

using device_id_t = uint64_t;

enum PiActProfApiSupport {
  PiActProfApiSupport_SET_MBRS = PI_ACT_PROF_API_SUPPORT_GRP_SET_MBRS,
  PiActProfApiSupport_ADD_AND_REMOVE_MBR =
    PI_ACT_PROF_API_SUPPORT_GRP_ADD_AND_REMOVE_MBR,
  PiActProfApiSupport_BOTH = PI_ACT_PROF_API_SUPPORT_GRP_SET_MBRS |
    PI_ACT_PROF_API_SUPPORT_GRP_ADD_AND_REMOVE_MBR,
};

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

  // used to capture handle for MC groups
  pi_status_t _mc_grp_create(pi_mc_grp_id_t grp_id,
                             pi_mc_grp_handle_t *grp_handle);

  pi_mc_grp_handle_t get_mc_grp_handle() const;

  // used to capture handle for MC nodes
  pi_status_t _mc_node_create(pi_mc_rid_t rid,
                              size_t eg_ports_count,
                              const pi_mc_port_t *eg_ports,
                              pi_mc_node_handle_t *node_handle);

  pi_mc_node_handle_t get_mc_node_handle() const;

  pi_status_t packetin_inject(const std::string &packet) const;

  pi_status_t digest_inject(pi_p4_id_t learn_id,
                            pi_learn_msg_id_t msg_id,
                            const std::vector<std::string> &samples) const;

  pi_status_t age_entry(pi_p4_id_t table_id,
                        pi_entry_handle_t entry_handle) const;

  void set_p4info(const pi_p4info_t *p4info);

  void reset();

  MOCK_METHOD4(table_entry_add,
               pi_status_t(pi_p4_id_t, const pi_match_key_t *,
                           const pi_table_entry_t *, pi_entry_handle_t *));
  MOCK_METHOD2(table_default_action_set,
               pi_status_t(pi_p4_id_t, const pi_table_entry_t *));
  MOCK_METHOD1(table_default_action_reset, pi_status_t(pi_p4_id_t));
  MOCK_METHOD2(table_default_action_get,
               pi_status_t(pi_p4_id_t, pi_table_entry_t *));
  MOCK_METHOD2(table_entry_delete_wkey,
               pi_status_t(pi_p4_id_t, const pi_match_key_t *));
  MOCK_METHOD3(table_entry_modify_wkey,
               pi_status_t(pi_p4_id_t, const pi_match_key_t *,
                           const pi_table_entry_t *));
  MOCK_METHOD2(table_entries_fetch,
               pi_status_t(pi_p4_id_t, pi_table_fetch_res_t *));
  MOCK_METHOD2(table_idle_timeout_config_set,
               pi_status_t(pi_p4_id_t, const pi_idle_timeout_config_t *));
  MOCK_METHOD3(table_entry_get_remaining_ttl,
               pi_status_t(pi_p4_id_t, pi_entry_handle_t, uint64_t *));

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
  MOCK_METHOD4(action_prof_group_set_members,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t,
                           size_t, const pi_indirect_handle_t *));
  MOCK_METHOD2(action_prof_entries_fetch,
               pi_status_t(pi_p4_id_t, pi_act_prof_fetch_res_t *));
  MOCK_METHOD0(action_prof_api_support, int());

  MOCK_METHOD3(meter_read,
               pi_status_t(pi_p4_id_t, size_t, pi_meter_spec_t *));
  MOCK_METHOD3(meter_set,
               pi_status_t(pi_p4_id_t, size_t, const pi_meter_spec_t *));
  MOCK_METHOD3(meter_read_direct,
               pi_status_t(pi_p4_id_t, pi_entry_handle_t, pi_meter_spec_t *));
  MOCK_METHOD3(meter_set_direct,
               pi_status_t(pi_p4_id_t, pi_entry_handle_t,
                           const pi_meter_spec_t *));

  MOCK_METHOD4(counter_read,
               pi_status_t(pi_p4_id_t, size_t, int, pi_counter_data_t *));
  MOCK_METHOD3(counter_write,
               pi_status_t(pi_p4_id_t, size_t, const pi_counter_data_t *));
  MOCK_METHOD4(counter_read_direct,
               pi_status_t(pi_p4_id_t, pi_entry_handle_t, int,
                           pi_counter_data_t *));
  MOCK_METHOD3(counter_write_direct,
               pi_status_t(pi_p4_id_t, pi_entry_handle_t,
                           const pi_counter_data_t *));

  MOCK_METHOD2(packetout_send, pi_status_t(const char *, size_t));

  MOCK_METHOD2(mc_grp_create,
               pi_status_t(pi_mc_grp_id_t, pi_mc_grp_handle_t *));
  MOCK_METHOD1(mc_grp_delete, pi_status_t(pi_mc_grp_handle_t));
  MOCK_METHOD4(mc_node_create,
               pi_status_t(pi_mc_rid_t, size_t, const pi_mc_port_t *,
                           pi_mc_node_handle_t *));
  MOCK_METHOD3(mc_node_modify,
               pi_status_t(pi_mc_node_handle_t, size_t, const pi_mc_port_t *));
  MOCK_METHOD1(mc_node_delete, pi_status_t(pi_mc_node_handle_t));
  MOCK_METHOD2(mc_grp_attach_node,
               pi_status_t(pi_mc_grp_handle_t, pi_mc_node_handle_t));
  MOCK_METHOD2(mc_grp_detach_node,
               pi_status_t(pi_mc_grp_handle_t, pi_mc_node_handle_t));

  MOCK_METHOD2(clone_session_set,
               pi_status_t(pi_clone_session_id_t,
                           const pi_clone_session_config_t *));
  MOCK_METHOD1(clone_session_reset, pi_status_t(pi_clone_session_id_t));

  MOCK_METHOD2(learn_config_set,
               pi_status_t(pi_p4_id_t, const pi_learn_config_t *));
  MOCK_METHOD2(learn_msg_ack, pi_status_t(pi_p4_id_t, pi_learn_msg_id_t));
  MOCK_METHOD1(learn_msg_done, pi_status_t(pi_learn_msg_t *));

 private:
  std::unique_ptr<DummySwitch> sw;
  pi_indirect_handle_t action_prof_h;
  pi_entry_handle_t table_h;
  pi_mc_grp_handle_t mc_grp_h;
  pi_mc_node_handle_t mc_node_h;
};

// used to map device ids to DummySwitchMock instances; thread safe in case we
// want to make tests run in parallel
class DeviceResolver {
 public:
  static device_id_t new_switch() {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    assert(r->map.size() <= (device_range_end - device_range_start));
    for (device_id_t id = device_range_start; id < device_range_end; id++) {
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

  // test 64-bit device id support
  static constexpr device_id_t device_range_start = 1ULL << 30;
  static constexpr device_id_t device_range_end = device_range_start + 256;

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
