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

#include "PI/pi.h"

#include <stdio.h>

#include "func_counter.h"

pi_status_t _pi_act_prof_mbr_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id,
                                    const pi_action_data_t *action_data,
                                    pi_indirect_handle_t *mbr_handle) {
  (void)session_handle;
  (void)dev_tgt;
  (void)act_prof_id;
  (void)action_data;
  (void)mbr_handle;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_mbr_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle) {
  (void)session_handle;
  (void)dev_id;
  (void)act_prof_id;
  (void)mbr_handle;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_mbr_modify(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle,
                                    const pi_action_data_t *action_data) {
  (void)session_handle;
  (void)dev_id;
  (void)act_prof_id;
  (void)mbr_handle;
  (void)action_data;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id, size_t max_size,
                                    pi_indirect_handle_t *grp_handle) {
  (void)session_handle;
  (void)dev_tgt;
  (void)act_prof_id;
  (void)max_size;
  (void)grp_handle;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle) {
  (void)session_handle;
  (void)dev_id;
  (void)act_prof_id;
  (void)grp_handle;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_add_mbr(pi_session_handle_t session_handle,
                                     pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                     pi_indirect_handle_t grp_handle,
                                     pi_indirect_handle_t mbr_handle) {
  (void)session_handle;
  (void)dev_id;
  (void)act_prof_id;
  (void)grp_handle;
  (void)mbr_handle;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_remove_mbr(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id,
                                        pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t grp_handle,
                                        pi_indirect_handle_t mbr_handle) {
  (void)session_handle;
  (void)dev_id;
  (void)act_prof_id;
  (void)grp_handle;
  (void)mbr_handle;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
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
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_entries_fetch(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id,
                                       pi_p4_id_t act_prof_id,
                                       pi_act_prof_fetch_res_t *res) {
  (void)session_handle;
  (void)dev_id;
  (void)act_prof_id;
  (void)res;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_entries_fetch_done(pi_session_handle_t session_handle,
                                            pi_act_prof_fetch_res_t *res) {
  (void)session_handle;
  (void)res;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

int _pi_act_prof_api_support(pi_dev_id_t dev_id) {
  (void)dev_id;
  func_counter_increment(__func__);
  return PI_ACT_PROF_API_SUPPORT_GRP_SET_MBRS |
         PI_ACT_PROF_API_SUPPORT_GRP_ADD_AND_REMOVE_MBR;
}
