/* Copyright 2026 Lorenzo Rinieri
 * SPDX-License-Identifier: Apache-2.0
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

#include <PI/p4info.h>
#include <PI/target/pi_register_imp.h>
#include <string.h>

#include "pi_rpc.h"

// The size of a cell, checked by the caller (see pi_register.c).
static size_t cell_size(pi_dev_id_t dev_id, pi_p4_id_t register_id) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_id);
  return (pi_p4info_register_get_bitwidth(p4info, register_id) + 7) / 8;
}

pi_status_t _pi_register_read(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                              size_t index, char *value) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t size = cell_size(dev_tgt.dev_id, register_id);

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_tgt_t dev_tgt;
    s_pi_p4_id_t register_id;
    uint64_t index;
    uint32_t size;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, PI_RPC_REGISTER_READ);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, register_id);
  req_ += emit_uint64(req_, index);
  req_ += emit_uint32(req_, size);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  // the reply header is followed by the value of the cell
  char *rep = NULL;
  int bytes = nn_recv(state.s, &rep, NN_MSG, 0);
  if (bytes <= 0) return PI_STATUS_RPC_TRANSPORT_ERROR;
  pi_status_t status = retrieve_rep_hdr(rep, req_id);
  if (status == PI_STATUS_SUCCESS) {
    if ((size_t)bytes != sizeof(rep_hdr_t) + size)
      status = PI_STATUS_RPC_TRANSPORT_ERROR;
    else
      memcpy(value, rep + sizeof(rep_hdr_t), size);
  }
  nn_freemsg(rep);
  return status;
}

// for PI_RPC_REGISTER_WRITE_ALL, index is ignored
static pi_status_t register_write(pi_rpc_type_t type,
                                  pi_session_handle_t session_handle,
                                  pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                                  uint64_t index, const char *value) {
  assert(type == PI_RPC_REGISTER_WRITE || type == PI_RPC_REGISTER_WRITE_ALL);

  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t size = cell_size(dev_tgt.dev_id, register_id);

  size_t s = 0;
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_session_handle_t);
  s += sizeof(s_pi_dev_tgt_t);
  s += sizeof(s_pi_p4_id_t);
  s += sizeof(uint64_t);  // index
  s += sizeof(uint32_t);  // size
  s += size;

  char *req = nn_allocmsg(s, 0);
  if (!req) return PI_STATUS_ALLOC_ERROR;
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, type);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, register_id);
  req_ += emit_uint64(req_, index);
  req_ += emit_uint32(req_, size);
  memcpy(req_, value, size);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t)rc != s) {
    nn_freemsg(req);
    return PI_STATUS_RPC_TRANSPORT_ERROR;
  }

  return wait_for_status(req_id);
}

pi_status_t _pi_register_write(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                               size_t index, const char *value) {
  return register_write(PI_RPC_REGISTER_WRITE, session_handle, dev_tgt,
                        register_id, index, value);
}

pi_status_t _pi_register_write_all(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                                   const char *value) {
  return register_write(PI_RPC_REGISTER_WRITE_ALL, session_handle, dev_tgt,
                        register_id, 0, value);
}
