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

#include <PI/target/pi_learn_imp.h>

#include <stdlib.h>
#include <stdio.h>

#include "pi_rpc.h"

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
