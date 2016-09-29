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

#include <PI/target/pi_counter_imp.h>

#include "pi_rpc.h"

static pi_status_t wait_for_counter_data(uint32_t req_id,
                                         pi_counter_data_t *counter_data) {
  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_counter_data_t counter_data;
  } rep_t;
  rep_t rep;
  int rc = nn_recv(state.s, &rep, sizeof(rep), 0);
  if (rc != sizeof(rep)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  pi_status_t status = retrieve_rep_hdr((char *)&rep, req_id);
  // really needed?
  if (status != PI_STATUS_SUCCESS) counter_data->valid = 0;
  retrieve_counter_data((char *)&rep.counter_data, counter_data);
  return status;
}

// same code whether it's direct or not
static pi_status_t counter_read(pi_rpc_type_t type,
                                pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                uint64_t h, int flags,
                                pi_counter_data_t *counter_data) {
  assert(type == PI_RPC_COUNTER_READ || type == PI_RPC_COUNTER_READ_DIRECT);

  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_tgt_t dev_tgt;
    s_pi_p4_id_t counter_id;
    uint64_t h;
    uint32_t flags;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, type);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, counter_id);
  req_ += emit_uint64(req_, h);
  req_ += emit_uint32(req_, flags);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_counter_data(req_id, counter_data);
}

// same code whether it's direct or not
static pi_status_t counter_write(pi_rpc_type_t type,
                                 pi_session_handle_t session_handle,
                                 pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                 uint64_t h,
                                 const pi_counter_data_t *counter_data) {
  assert(type == PI_RPC_COUNTER_WRITE || type == PI_RPC_COUNTER_WRITE_DIRECT);

  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_tgt_t dev_tgt;
    s_pi_p4_id_t counter_id;
    uint64_t h;
    s_pi_counter_data_t counter_data;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, type);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, counter_id);
  req_ += emit_uint64(req_, h);
  req_ += emit_counter_data(req_, counter_data);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_counter_read(pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                             size_t index, int flags,
                             pi_counter_data_t *counter_data) {
  return counter_read(PI_RPC_COUNTER_READ, session_handle, dev_tgt, counter_id,
                      index, flags, counter_data);
}

pi_status_t _pi_counter_write(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                              size_t index,
                              const pi_counter_data_t *counter_data) {
  return counter_write(PI_RPC_COUNTER_WRITE, session_handle, dev_tgt,
                       counter_id, index, counter_data);
}

pi_status_t _pi_counter_read_direct(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                    pi_entry_handle_t entry_handle, int flags,
                                    pi_counter_data_t *counter_data) {
  return counter_read(PI_RPC_COUNTER_READ_DIRECT, session_handle, dev_tgt,
                      counter_id, entry_handle, flags, counter_data);
}

pi_status_t _pi_counter_write_direct(pi_session_handle_t session_handle,
                                     pi_dev_tgt_t dev_tgt,
                                     pi_p4_id_t counter_id,
                                     pi_entry_handle_t entry_handle,
                                     const pi_counter_data_t *counter_data) {
  return counter_write(PI_RPC_COUNTER_WRITE_DIRECT, session_handle, dev_tgt,
                       counter_id, entry_handle, counter_data);
}

pi_status_t _pi_counter_hw_sync(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                PICounterHwSyncCb cb, void *cb_cookie) {
  (void)session_handle;
  (void)dev_tgt;
  (void)counter_id;
  (void)cb;
  (void)cb_cookie;
  return PI_STATUS_RPC_NOT_IMPLEMENTED;
}
