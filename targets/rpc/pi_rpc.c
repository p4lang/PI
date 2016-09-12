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

#include "pi_rpc.h"

char *rpc_addr = NULL;
char *notifications_addr = NULL;

pi_rpc_state_t state;

pi_status_t retrieve_rep_hdr(const char *rep, pi_rpc_id_t req_id) {
  pi_rpc_id_t recv_id;
  pi_status_t recv_status;
  rep += retrieve_rpc_id(rep, &recv_id);
  if (recv_id != req_id) return PI_STATUS_RPC_TRANSPORT_ERROR;
  rep += retrieve_status(rep, &recv_status);

  return recv_status;
}

pi_status_t wait_for_status(pi_rpc_id_t req_id) {
  rep_hdr_t rep;
  int rc = nn_recv(state.s, &rep, sizeof(rep), 0);
  if (rc != sizeof(rep)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  return retrieve_rep_hdr((char *)&rep, req_id);
}

size_t emit_req_hdr(char *hdr, pi_rpc_id_t id, pi_rpc_type_t type) {
  size_t s = 0;
  s += emit_rpc_id(hdr, id);
  s += emit_rpc_type(hdr + s, type);
  return s;
}
