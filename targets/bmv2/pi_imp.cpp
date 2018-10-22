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
#include <PI/target/pi_imp.h>

#include <iostream>
#include <string>

#include <cstring>  // for memset

#include "common.h"
#include "conn_mgr.h"
#include "cpu_send_recv.h"

namespace pibmv2 {

conn_mgr_t *conn_mgr_state = nullptr;

}  // namespace pibmv2

namespace {

pibmv2::CpuSendRecv *cpu_send_recv = nullptr;

}  // namespace

extern "C" {

pi_status_t _pi_init(void *extra) {
  (void) extra;
  pibmv2::device_info_state = new pibmv2::DeviceInfo();
  pibmv2::conn_mgr_state = pibmv2::conn_mgr_create();
  cpu_send_recv = new pibmv2::CpuSendRecv();
  cpu_send_recv->start();
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra) {
  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(!d_info->assigned);
  int rpc_port_num = -1;
  std::string bm_notifications_addr("");
  for (; !extra->end_of_extras; extra++) {
    std::string key(extra->key);
    if (key == "port" && extra->v) {
      try {
        rpc_port_num = std::stoi(std::string(extra->v), nullptr, 0);
      }
      catch (const std::exception& e) {
        return PI_STATUS_INVALID_INIT_EXTRA_PARAM;
      }
    } else if (key == "notifications" && extra->v) {
      bm_notifications_addr = std::string(extra->v);
    } else if (key == "cpu_iface" && extra->v) {
      int rc = cpu_send_recv->add_device(std::string(extra->v), dev_id);
      if (rc < 0) return PI_STATUS_INVALID_INIT_EXTRA_PARAM;
    }
  }
  if (rpc_port_num == -1) return PI_STATUS_MISSING_INIT_EXTRA_PARAM;
  if (conn_mgr_client_init(pibmv2::conn_mgr_state, dev_id, rpc_port_num))
    return PI_STATUS_TARGET_TRANSPORT_ERROR;

  d_info->p4info = p4info;
  d_info->assigned = 1;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_update_device_start(pi_dev_id_t dev_id,
                                    const pi_p4info_t *p4info,
                                    const char *device_data,
                                    size_t device_data_size) {
  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  std::string new_config(device_data, device_data_size);

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);
  try {
    client.c->bm_load_new_config(std::move(new_config));
  } catch (InvalidSwapOperation &iso) {
    const char *what =
        _SwapOperationErrorCode_VALUES_TO_NAMES.find(iso.code)->second;
    std::cout << "Invalid swap operation (" << iso.code << "): "
              << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + iso.code);
  }

  d_info->p4info = p4info;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_update_device_end(pi_dev_id_t dev_id) {
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);
  try {
    client.c->bm_swap_configs();
  } catch (InvalidSwapOperation &iso) {
    const char *what =
        _SwapOperationErrorCode_VALUES_TO_NAMES.find(iso.code)->second;
    std::cout << "Invalid swap operation (" << iso.code << "): "
              << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + iso.code);
  }
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_remove_device(pi_dev_id_t dev_id) {
  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  pibmv2::conn_mgr_client_close(pibmv2::conn_mgr_state, dev_id);
  cpu_send_recv->remove_device(dev_id);
  d_info->assigned = 0;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_destroy() {
  pibmv2::conn_mgr_destroy(pibmv2::conn_mgr_state);
  delete cpu_send_recv;
  return PI_STATUS_SUCCESS;
}

// bmv2 does not support transaction and has no use for the session_handle
pi_status_t _pi_session_init(pi_session_handle_t *session_handle) {
  *session_handle = 0;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_session_cleanup(pi_session_handle_t session_handle) {
  (void) session_handle;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_batch_begin(pi_session_handle_t session_handle) {
  (void) session_handle;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_batch_end(pi_session_handle_t session_handle, bool hw_sync) {
  (void) session_handle;
  (void) hw_sync;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                               size_t size) {
  if (cpu_send_recv->send_pkt(dev_id, pkt, size) != 0)
    return PI_STATUS_PACKETOUT_SEND_ERROR;
  return PI_STATUS_SUCCESS;
}

}
