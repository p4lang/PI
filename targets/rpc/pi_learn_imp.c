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

#include <PI/target/pi_learn_imp.h>

#include <stdio.h>
#include <stdlib.h>

#include "pi_rpc.h"

pi_status_t _pi_learn_config_set(pi_session_handle_t session_handle,
                                 pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                 const pi_learn_config_t *config) {
  (void)session_handle;
  (void)dev_id;
  (void)learn_id;
  (void)config;
  return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_learn_msg_ack(pi_session_handle_t session_handle,
                              pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                              pi_learn_msg_id_t msg_id) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t learn_id;
    s_pi_learn_msg_id_t msg_id;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, PI_RPC_LEARN_MSG_ACK);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, learn_id);
  req_ += emit_learn_msg_id(req_, msg_id);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req_t)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_learn_msg_done(pi_learn_msg_t *msg) {
  free(msg->entries);
  free(msg);
  return PI_STATUS_SUCCESS;
}
