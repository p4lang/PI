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

#include "PI/pi_tables.h"
#include "PI/target/pi_act_prof_imp.h"

pi_status_t pi_act_prof_mbr_create(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt,
                                   pi_p4_id_t act_prof_id,
                                   const pi_action_data_t *action_data,
                                   pi_indirect_handle_t *mbr_handle) {
  return _pi_act_prof_mbr_create(session_handle, dev_tgt, act_prof_id,
                                 action_data, mbr_handle);
}

pi_status_t pi_act_prof_mbr_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t mbr_handle) {
  return _pi_act_prof_mbr_delete(session_handle, dev_id, act_prof_id,
                                 mbr_handle);
}

pi_status_t pi_act_prof_mbr_modify(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t mbr_handle,
                                   const pi_action_data_t *action_data) {
  return _pi_act_prof_mbr_modify(session_handle, dev_id, act_prof_id,
                                 mbr_handle, action_data);
}

pi_status_t pi_act_prof_grp_create(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt,
                                   pi_p4_id_t act_prof_id,
                                   size_t max_size,
                                   pi_indirect_handle_t *grp_handle) {
  return _pi_act_prof_grp_create(session_handle, dev_tgt, act_prof_id,
                                 max_size, grp_handle);
}

pi_status_t pi_act_prof_grp_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_p4_id_t act_prof_id,
                                   pi_indirect_handle_t grp_handle) {
  return _pi_act_prof_grp_delete(session_handle, dev_id, act_prof_id,
                                 grp_handle);
}

pi_status_t pi_act_prof_grp_add_mbr(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id,
                                    pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle,
                                    pi_indirect_handle_t mbr_handle) {
  return _pi_act_prof_grp_add_mbr(session_handle, dev_id, act_prof_id,
                                  grp_handle, mbr_handle);
}

pi_status_t pi_act_prof_grp_remove_mbr(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id,
                                       pi_p4_id_t act_prof_id,
                                       pi_indirect_handle_t grp_handle,
                                       pi_indirect_handle_t mbr_handle) {
  return _pi_act_prof_grp_remove_mbr(session_handle, dev_id, act_prof_id,
                                     grp_handle, mbr_handle);
}
