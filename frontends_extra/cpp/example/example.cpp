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

#include <cstring>
#include <fstream>
#include <streambuf>
#include <string>

#include "_assert.h"
// auto-generated #define's
#include "pi_fe_defines_p4.h"

namespace {

pi_p4info_t *p4info = nullptr;
pi_session_handle_t sess;
pi_dev_tgt_t dev_tgt = {0, 0xffff};

// easy to read version
int add_route(uint32_t prefix, int pLen, uint32_t nhop, uint16_t port,
              pi_entry_handle_t *handle) {
  pi::error_code_t rc = 0;

  // match key
  pi::MatchKey match_key(p4info, PI_P4_TABLE_IPV4_LPM);
  rc |= match_key.set_lpm(PI_P4_MF_IPV4_LPM_IPV4_DSTADDR, prefix, pLen);

  // action data
  pi::ActionEntry action_entry;
  action_entry.init_action_data(p4info, PI_P4_ACTION_SET_NHOP);
  auto action_data = action_entry.mutable_action_data();
  rc |= action_data->set_arg(PI_P4_ACTIONP_SET_NHOP_NHOP_IPV4, nhop);
  rc |= action_data->set_arg(PI_P4_ACTIONP_SET_NHOP_PORT, port);

  pi::MatchTable mt(sess, dev_tgt, p4info, PI_P4_TABLE_IPV4_LPM);
  rc |= mt.entry_add(match_key, action_entry, true, handle);

  return rc;
}

// static thread_local data structures (no per-call heap allocation) => faster
int add_route_fast(uint32_t prefix, int pLen, uint32_t nhop, uint16_t port,
                   pi_entry_handle_t *handle) {
  pi::error_code_t rc = 0;

  // match key
  thread_local pi::MatchKey match_key(p4info, PI_P4_TABLE_IPV4_LPM);
  match_key.reset();
  rc |= match_key.set_lpm(PI_P4_MF_IPV4_LPM_IPV4_DSTADDR, prefix, pLen);

  // action data
  thread_local pi::ActionEntry action_entry;
  action_entry.init_action_data(p4info, PI_P4_ACTION_SET_NHOP);
  auto action_data = action_entry.mutable_action_data();
  action_data->reset();
  rc |= action_data->set_arg(PI_P4_ACTIONP_SET_NHOP_NHOP_IPV4, nhop);
  rc |= action_data->set_arg(PI_P4_ACTIONP_SET_NHOP_PORT, port);

  // so far no state in MatchTable and construction is cheap
  pi::MatchTable mt(sess, dev_tgt, p4info, PI_P4_TABLE_IPV4_LPM);
  rc |= mt.entry_add(match_key, action_entry, true, handle);

  return rc;
}

}  // namespace

int main() {
  pi_init(256, NULL);  // 256 max devices
  std::ifstream istream(TESTDATADIR "/" "simple_router.json");
  std::string config((std::istreambuf_iterator<char>(istream)),
                     std::istreambuf_iterator<char>());
  pi_add_config(config.c_str(), PI_CONFIG_TYPE_BMV2_JSON, &p4info);

  pi_assign_extra_t assign_options[2];
  memset(assign_options, 0, sizeof(assign_options));
  pi_assign_extra_t *rpc_port = &assign_options[0];
  rpc_port->key = "port";
  rpc_port->v = "9090";
  assign_options[1].end_of_extras = true;
  pi_assign_device(0, NULL, assign_options);
  pi_update_device_start(0, p4info, config.c_str(), config.size());
  pi_update_device_end(0);

  pi_session_init(&sess);

  pi_entry_handle_t handle;
  // Adding entry 10.0.0.1/8 => nhop=10.0.0.1, port=11
  uint32_t ipv4_dstAddr = 0x0a000001;
  uint16_t port_1 = 7;
  uint16_t port_2 = 8;
  _PI_ASSERT(!add_route(ipv4_dstAddr, 8, ipv4_dstAddr, port_1, &handle));
  _PI_ASSERT(!add_route_fast(ipv4_dstAddr, 16, ipv4_dstAddr, port_2, &handle));

  pi_session_cleanup(sess);

  pi_remove_device(0);

  pi_destroy_config(p4info);
}
