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
#include <PI/p4info.h>
#include <PI/target/pi_learn_imp.h>

#include <bm/bm_apps/learn.h>

#include <string>

#include <cstdio>

#include "common.h"

namespace {

// TODO(antonin): support for multi-devices
bm_apps::LearnListener *learn_listener = NULL;

size_t get_learn_sample_size(const pi_p4info_t *p4info,
                             pi_p4_id_t field_list_id) {
  size_t num_fields = 0;
  const pi_p4_id_t *fids = pi_p4info_field_list_get_fields(
      p4info, field_list_id, &num_fields);
  size_t s = 0;
  for (size_t i = 0; i < num_fields; i++) {
    s += (pi_p4info_field_bitwidth(p4info, fids[i]) + 7) / 8;
  }
  return s;
}

void cb_fn(const bm_apps::LearnListener::MsgInfo &msg_info,
           const char *data, void *cookie) {
  (void)cookie;
  pibmv2::device_info_t *d_info = pibmv2::get_device_info(msg_info.switch_id);
  if (!d_info) {
    printf("Unknown switch id\n");
    return;
  }
  const pi_p4info_t *p4info = d_info->p4info;
  assert(p4info);
  pi_learn_msg_t *msg = new pi_learn_msg_t;
  msg->dev_tgt.dev_id = msg_info.switch_id;
  msg->dev_tgt.dev_pipe_mask = msg_info.cxt_id;
  // total hack for now
  msg->learn_id = (PI_FIELD_LIST_ID << 24) | (msg_info.list_id - 1);
  msg->msg_id = msg_info.buffer_id;
  msg->num_entries = msg_info.num_samples;
  msg->entry_size = get_learn_sample_size(p4info, msg->learn_id);
  msg->entries = const_cast<char *>(data);  // ouch
  pi_learn_new_msg(msg);
}

}  // namespace

namespace pibmv2 {

void start_learn_listener(const std::string &addr, int rpc_port_num) {
  learn_listener = new bm_apps::LearnListener(addr, "localhost", rpc_port_num);
  learn_listener->register_cb(cb_fn, NULL);
  learn_listener->start();
}

void stop_learn_listener() {
  if (learn_listener) delete learn_listener;
}

}  // namespace pibmv2

extern "C" {

pi_status_t _pi_learn_msg_ack(pi_session_handle_t session_handle,
                              pi_dev_id_t dev_id,
                              pi_p4_id_t learn_id,
                              pi_learn_msg_id_t msg_id) {
  (void)session_handle;
  (void)dev_id;
  if (!learn_listener) return PI_STATUS_TARGET_ERROR;
  bm_apps::LearnListener::list_id_t id = (0xffffff & learn_id) + 1;
  learn_listener->ack_buffer(0, id, msg_id);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_learn_msg_done(pi_learn_msg_t *msg) {
  delete msg;
  return PI_STATUS_SUCCESS;
}

}
