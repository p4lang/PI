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
