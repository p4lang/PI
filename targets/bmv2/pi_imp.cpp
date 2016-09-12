/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <PI/pi.h>
#include <PI/target/pi_imp.h>

#include <string>
#include <cstring>  // for memset

#include "conn_mgr.h"
#include "common.h"
#include "cpu_send_recv.h"

#define NUM_DEVICES 256

namespace pibmv2 {

conn_mgr_t *conn_mgr_state = NULL;

device_info_t device_info_state[NUM_DEVICES];

extern void start_learn_listener(const std::string &addr, int rpc_port_num);
extern void stop_learn_listener();

}  // namespace pibmv2

namespace {

pibmv2::CpuSendRecv *cpu_send_recv = nullptr;

}  // namespace

extern "C" {

pi_status_t _pi_init(void *extra) {
  (void) extra;
  memset(pibmv2::device_info_state, 0, sizeof(pibmv2::device_info_state));
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

  if (bm_notifications_addr != "")
    pibmv2::start_learn_listener(bm_notifications_addr, rpc_port_num);

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
  pibmv2::stop_learn_listener();
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

pi_status_t _pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                               size_t size) {
  if (cpu_send_recv->send_pkt(dev_id, pkt, size) != 0)
    return PI_STATUS_PACKETOUT_SEND_ERROR;
  return PI_STATUS_SUCCESS;
}

}
