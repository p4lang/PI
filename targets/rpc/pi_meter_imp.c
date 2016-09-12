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
