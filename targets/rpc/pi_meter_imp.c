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

#include <PI/target/pi_meter_imp.h>

#include "pi_rpc.h"

static pi_status_t wait_for_meter_spec(uint32_t req_id,
                                       pi_meter_spec_t *meter_spec) {
  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_meter_spec_t meter_spec;
  } rep_t;
  rep_t rep;
  int rc = nn_recv(state.s, &rep, sizeof(rep), 0);
  if (rc != sizeof(rep)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  pi_status_t status = retrieve_rep_hdr((char *)&rep, req_id);
  // condition on success?
  retrieve_meter_spec((char *)&rep.meter_spec, meter_spec);
  return status;
}

// same code whether it's direct or not
static pi_status_t meter_read(pi_rpc_type_t type,
                              pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                              uint64_t h, pi_meter_spec_t *meter_spec) {
  assert(type == PI_RPC_METER_READ || type == PI_RPC_METER_READ_DIRECT);

  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_tgt_t dev_tgt;
    s_pi_p4_id_t meter_id;
    uint64_t h;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, type);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, meter_id);
  req_ += emit_uint64(req_, h);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_meter_spec(req_id, meter_spec);
}

// same code whether it's direct or not
static pi_status_t meter_set(pi_rpc_type_t type,
                             pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                             uint64_t h, const pi_meter_spec_t *meter_spec) {
  assert(type == PI_RPC_METER_SET || type == PI_RPC_METER_SET_DIRECT);

  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_tgt_t dev_tgt;
    s_pi_p4_id_t meter_id;
    uint64_t h;
    s_pi_meter_spec_t meter_spec;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, type);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, meter_id);
  req_ += emit_uint64(req_, h);
  req_ += emit_meter_spec(req_, meter_spec);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_meter_read(pi_session_handle_t session_handle,
                           pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                           size_t index, pi_meter_spec_t *meter_spec) {
  return meter_read(PI_RPC_METER_READ, session_handle, dev_tgt, meter_id, index,
                    meter_spec);
}

pi_status_t _pi_meter_set(pi_session_handle_t session_handle,
                          pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                          size_t index, const pi_meter_spec_t *meter_spec) {
  return meter_set(PI_RPC_METER_SET, session_handle, dev_tgt, meter_id, index,
                   meter_spec);
}

pi_status_t _pi_meter_read_direct(pi_session_handle_t session_handle,
                                  pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                  pi_entry_handle_t entry_handle,
                                  pi_meter_spec_t *meter_spec) {
  return meter_read(PI_RPC_METER_READ_DIRECT, session_handle, dev_tgt, meter_id,
                    entry_handle, meter_spec);
}

pi_status_t _pi_meter_set_direct(pi_session_handle_t session_handle,
                                 pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                 pi_entry_handle_t entry_handle,
                                 const pi_meter_spec_t *meter_spec) {
  return meter_set(PI_RPC_METER_SET_DIRECT, session_handle, dev_tgt, meter_id,
                   entry_handle, meter_spec);
}
