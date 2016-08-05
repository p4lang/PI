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

#include "pi_rpc.h"

#include <stdio.h>

static pi_status_t wait_for_handle(uint32_t req_id,
                                   pi_indirect_handle_t *h) {
  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_indirect_handle_t h;
  } rep_t;
  rep_t rep;
  int rc = nn_recv(state.s, &rep, sizeof(rep), 0);
  if (rc != sizeof(rep)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  pi_status_t status = retrieve_rep_hdr((char *) &rep, req_id);
  // condition on success?
  retrieve_indirect_handle((char *) &rep.h, h);
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
  assert((size_t) (req_ - req) == s);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t) rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_handle(req_id, mbr_handle);
}

pi_status_t _pi_act_prof_mbr_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id,
                                    pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle) {
  (void) session_handle; (void) dev_id; (void) act_prof_id; (void) mbr_handle;
  printf("%s\n", __func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_mbr_modify(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id,
                                    pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle,
                                    const pi_action_data_t *action_data) {
  (void) session_handle; (void) dev_id; (void) act_prof_id; (void) mbr_handle;
  (void) action_data;
  printf("%s\n", __func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t *grp_handle) {
  (void) session_handle; (void) dev_tgt; (void) act_prof_id; (void) grp_handle;
  printf("%s\n", __func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id,
                                    pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle) {
  (void) session_handle; (void) dev_id; (void) act_prof_id; (void) grp_handle;
  printf("%s\n", __func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_add_mbr(pi_session_handle_t session_handle,
                                     pi_dev_id_t dev_id,
                                     pi_p4_id_t act_prof_id,
                                     pi_indirect_handle_t grp_handle,
                                     pi_indirect_handle_t mbr_handle) {
  (void) session_handle; (void) dev_id; (void) act_prof_id; (void) grp_handle;
  (void) mbr_handle;
  printf("%s\n", __func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_remove_mbr(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id,
                                        pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t grp_handle,
                                        pi_indirect_handle_t mbr_handle) {
  (void) session_handle; (void) dev_id; (void) act_prof_id; (void) grp_handle;
  (void) mbr_handle;
  printf("%s\n", __func__);
  return PI_STATUS_SUCCESS;
}
