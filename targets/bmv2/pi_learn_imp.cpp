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
  printf("YEAAAAAAAAAAAAA\n");
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
