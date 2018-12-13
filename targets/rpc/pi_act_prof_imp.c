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

#include <PI/target/pi_act_prof_imp.h>

#include "pi_rpc.h"

#include <stdlib.h>
#include <string.h>

static pi_status_t wait_for_handle(uint32_t req_id, pi_indirect_handle_t *h) {
  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_indirect_handle_t h;
  } rep_t;
  rep_t rep;
  int rc = nn_recv(state.s, &rep, sizeof(rep), 0);
  if (rc != sizeof(rep)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  pi_status_t status = retrieve_rep_hdr((char *)&rep, req_id);
  // condition on success?
  retrieve_indirect_handle((char *)&rep.h, h);
  return status;
}

pi_status_t _pi_act_prof_mbr_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id,
                                    const pi_action_data_t *action_data,
                                    pi_indirect_handle_t *mbr_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_session_handle_t);
  s += sizeof(s_pi_dev_tgt_t);
  s += sizeof(s_pi_p4_id_t);  // act_prof_id
  s += action_data_size(action_data);

  char *req = nn_allocmsg(s, 0);
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_ACT_PROF_MBR_CREATE);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, act_prof_id);
  req_ += emit_action_data(req_, action_data);

  // make sure I have copied exactly the right amount
  assert((size_t)(req_ - req) == s);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t)rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_handle(req_id, mbr_handle);
}

pi_status_t _pi_act_prof_mbr_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t act_prof_id;
    s_pi_indirect_handle_t h;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, PI_RPC_ACT_PROF_MBR_DELETE);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, act_prof_id);
  req_ += emit_indirect_handle(req_, mbr_handle);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_act_prof_mbr_modify(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle,
                                    const pi_action_data_t *action_data) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_session_handle_t);
  s += sizeof(s_pi_dev_id_t);
  s += sizeof(s_pi_p4_id_t);  // act_prof_id
  s += sizeof(s_pi_indirect_handle_t);
  s += action_data_size(action_data);

  char *req = nn_allocmsg(s, 0);
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_ACT_PROF_MBR_MODIFY);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, act_prof_id);
  req_ += emit_indirect_handle(req_, mbr_handle);
  req_ += emit_action_data(req_, action_data);

  // make sure I have copied exactly the right amount
  assert((size_t)(req_ - req) == s);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t)rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_act_prof_grp_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id, size_t max_size,
                                    pi_indirect_handle_t *grp_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_tgt_t dev_tgt;
    s_pi_p4_id_t act_prof_id;
    uint32_t max_size;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, PI_RPC_ACT_PROF_GRP_CREATE);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, act_prof_id);
  req_ += emit_uint32(req_, max_size);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_handle(req_id, grp_handle);
}

pi_status_t _pi_act_prof_grp_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t act_prof_id;
    s_pi_indirect_handle_t h;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, PI_RPC_ACT_PROF_GRP_DELETE);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, act_prof_id);
  req_ += emit_indirect_handle(req_, grp_handle);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

static pi_status_t grp_add_remove_mbr(pi_session_handle_t session_handle,
                                      pi_dev_id_t dev_id,
                                      pi_p4_id_t act_prof_id,
                                      pi_indirect_handle_t grp_handle,
                                      pi_indirect_handle_t mbr_handle,
                                      pi_rpc_type_t add_or_remove) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t act_prof_id;
    s_pi_indirect_handle_t grp_h;
    s_pi_indirect_handle_t mbr_h;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;

  req_ += emit_req_hdr(req_, req_id, add_or_remove);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, act_prof_id);
  req_ += emit_indirect_handle(req_, grp_handle);
  req_ += emit_indirect_handle(req_, mbr_handle);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_act_prof_grp_add_mbr(pi_session_handle_t session_handle,
                                     pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                     pi_indirect_handle_t grp_handle,
                                     pi_indirect_handle_t mbr_handle) {
  return grp_add_remove_mbr(session_handle, dev_id, act_prof_id, grp_handle,
                            mbr_handle, PI_RPC_ACT_PROF_GRP_ADD_MBR);
}

pi_status_t _pi_act_prof_grp_remove_mbr(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id,
                                        pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t grp_handle,
                                        pi_indirect_handle_t mbr_handle) {
  return grp_add_remove_mbr(session_handle, dev_id, act_prof_id, grp_handle,
                            mbr_handle, PI_RPC_ACT_PROF_GRP_REMOVE_MBR);
}

pi_status_t _pi_act_prof_grp_set_mbrs(pi_session_handle_t session_handle,
                                      pi_dev_id_t dev_id,
                                      pi_p4_id_t act_prof_id,
                                      pi_indirect_handle_t grp_handle,
                                      size_t num_mbrs,
                                      const pi_indirect_handle_t *mbr_handles) {
  (void)session_handle;
  (void)dev_id;
  (void)act_prof_id;
  (void)grp_handle;
  (void)num_mbrs;
  (void)mbr_handles;
  return PI_STATUS_RPC_NOT_IMPLEMENTED;
}

pi_status_t _pi_act_prof_entries_fetch(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id,
                                       pi_p4_id_t act_prof_id,
                                       pi_act_prof_fetch_res_t *res) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t act_prof_id;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_ACT_PROF_ENTRIES_FETCH);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, act_prof_id);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  char *rep = NULL;
  int bytes = nn_recv(state.s, &rep, NN_MSG, 0);
  if (bytes <= 0) return PI_STATUS_RPC_TRANSPORT_ERROR;

  char *rep_ = rep;
  pi_status_t status = retrieve_rep_hdr(rep_, req_id);
  if (status != PI_STATUS_SUCCESS) {
    nn_freemsg(rep);
    return status;
  }
  rep_ += sizeof(rep_hdr_t);

  uint32_t tmp32;
  rep_ += retrieve_uint32(rep_, &tmp32);
  res->num_members = tmp32;
  rep_ += retrieve_uint32(rep_, &tmp32);
  res->num_groups = tmp32;

  rep_ += retrieve_uint32(rep_, &tmp32);
  res->entries_members_size = tmp32;
  res->entries_members = malloc(res->entries_members_size);
  memcpy(res->entries_members, rep_, res->entries_members_size);
  rep_ += res->entries_members_size;

  rep_ += retrieve_uint32(rep_, &tmp32);
  res->entries_groups_size = tmp32;
  res->entries_groups = malloc(res->entries_groups_size);
  memcpy(res->entries_groups, rep_, res->entries_groups_size);
  rep_ += res->entries_groups_size;

  rep_ += retrieve_uint32(rep_, &tmp32);
  res->num_cumulated_mbr_handles = tmp32;
  assert(sizeof(pi_indirect_handle_t) == sizeof(s_pi_indirect_handle_t));
  size_t mbr_handles_size = tmp32 * sizeof(pi_indirect_handle_t);
  res->mbr_handles = malloc(mbr_handles_size);
  memcpy(res->mbr_handles, rep_, mbr_handles_size);

  nn_freemsg(rep);
  return status;
}

pi_status_t _pi_act_prof_entries_fetch_done(pi_session_handle_t session_handle,
                                            pi_act_prof_fetch_res_t *res) {
  (void)session_handle;
  free(res->entries_members);
  free(res->entries_groups);
  free(res->mbr_handles);
  return PI_STATUS_SUCCESS;
}

int _pi_act_prof_api_support(pi_dev_id_t dev_id) {
  (void)dev_id;
  return PI_ACT_PROF_API_SUPPORT_GRP_SET_MBRS |
         PI_ACT_PROF_API_SUPPORT_GRP_ADD_AND_REMOVE_MBR;
}
