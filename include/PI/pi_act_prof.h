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

#ifndef PI_INC_PI_PI_ACT_PROF_H_
#define PI_INC_PI_PI_ACT_PROF_H_

pi_status_t pi_act_prof_mbr_create(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt,
                                   pi_p4_id_t act_prof_id,
                                   const pi_action_data_t *action_data,
                                   pi_indirect_handle_t *mbr_handle);

pi_status_t pi_act_prof_mbr_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t mbr_handle);

pi_status_t pi_act_prof_mbr_modify(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t mbr_handle,
                                   const pi_action_data_t *action_data);

pi_status_t pi_act_prof_grp_create(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt,
                                   pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t *grp_handle);

pi_status_t pi_act_prof_grp_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t grp_handle);

pi_status_t pi_act_prof_grp_add_mbr(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id,
                                    pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle,
                                    pi_indirect_handle_t mbr_handle);

pi_status_t pi_act_prof_grp_remove_mbr(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id,
                                       pi_p4_id_t act_prof_id,
                                       pi_indirect_handle_t grp_handle,
                                       pi_indirect_handle_t mbr_handle);

#endif  // PI_INC_PI_PI_ACT_PROF_H_
