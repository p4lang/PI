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

#include "conn_mgr.h"
#include "common.h"

#include "PI/pi.h"

#include <string>
#include <cstring>  // for memset

#define NUM_DEVICES 256

conn_mgr_t *conn_mgr_state = NULL;

device_info_t device_info_state[NUM_DEVICES];

extern "C" {

pi_status_t _pi_init() {
  memset(device_info_state, 0, sizeof(device_info_state));
  conn_mgr_state = conn_mgr_create();
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_assign_device(uint16_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra) {
  device_info_t *d_info = get_device_info(dev_id);
  assert(!d_info->assigned);
  int rpc_port_num = -1;
  for (; !extra->end_of_extras; extra++) {
    std::string key(extra->key);
    if (key == "port" && extra->v) {
      try {
        rpc_port_num = std::stoi(std::string(extra->v), nullptr, 0);
      }
      catch (const std::exception& e) {
        return PI_STATUS_INVALID_INIT_EXTRA_PARAM;
      }
    }
  }
  if (rpc_port_num == -1) return PI_STATUS_MISSING_INIT_EXTRA_PARAM;
  if (conn_mgr_client_init(conn_mgr_state, dev_id, rpc_port_num))
    return PI_STATUS_TARGET_TRANSPORT_ERROR;
  d_info->p4info = p4info;
  d_info->assigned = 1;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_remove_device(uint16_t dev_id) {
  device_info_t *d_info = get_device_info(dev_id);
  assert(d_info->assigned);
  conn_mgr_client_close(conn_mgr_state, dev_id);
  d_info->assigned = 0;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_destroy() {
  conn_mgr_destroy(conn_mgr_state);
  return PI_STATUS_SUCCESS;
}

}
