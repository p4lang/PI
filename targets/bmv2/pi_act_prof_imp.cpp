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

#include <PI/int/pi_int.h>
#include <PI/p4info.h>
#include <PI/pi.h>

#include <iostream>
#include <string>
#include <vector>

#include "action_helpers.h"
#include "common.h"
#include "conn_mgr.h"

namespace pibmv2 {

extern conn_mgr_t *conn_mgr_state;

}  // namespace pibmv2

extern "C" {

pi_status_t _pi_act_prof_mbr_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id,
                                    const pi_action_data_t *action_data,
                                    pi_indirect_handle_t *mbr_handle) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  auto adata = pibmv2::build_action_data(action_data, p4info);
  std::string ap_name(pi_p4info_act_prof_name_from_id(p4info, act_prof_id));
  std::string a_name(pi_p4info_action_name_from_id(p4info,
                                                   action_data->action_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);

  try {
    *mbr_handle = client.c->bm_mt_act_prof_add_member(
        0, ap_name, a_name, adata);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid action profile (" << ap_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_mbr_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id,
                                    pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string ap_name(pi_p4info_act_prof_name_from_id(p4info, act_prof_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  try {
    client.c->bm_mt_act_prof_delete_member(0, ap_name, mbr_handle);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid action profile (" << ap_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_mbr_modify(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id,
                                    pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle,
                                    const pi_action_data_t *action_data) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  auto adata = pibmv2::build_action_data(action_data, p4info);
  std::string ap_name(pi_p4info_act_prof_name_from_id(p4info, act_prof_id));
  std::string a_name(pi_p4info_action_name_from_id(p4info,
                                                   action_data->action_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  try {
    client.c->bm_mt_act_prof_modify_member(
        0, ap_name, mbr_handle, a_name, adata);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid action profile (" << ap_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_create(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id,
                                    size_t max_size,
                                    pi_indirect_handle_t *grp_handle) {
  (void) session_handle;
  (void) max_size;  // no bound needed / supported in bmv2

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string ap_name(pi_p4info_act_prof_name_from_id(p4info, act_prof_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);

  try {
    *grp_handle = client.c->bm_mt_act_prof_create_group(0, ap_name);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid action profile (" << ap_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  *grp_handle = pibmv2::IndirectHMgr::make_grp_h(*grp_handle);

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_delete(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id,
                                    pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string ap_name(pi_p4info_act_prof_name_from_id(p4info, act_prof_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  try {
    client.c->bm_mt_act_prof_delete_group(0, ap_name, grp_handle);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid action profile (" << ap_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_add_mbr(pi_session_handle_t session_handle,
                                     pi_dev_id_t dev_id,
                                     pi_p4_id_t act_prof_id,
                                     pi_indirect_handle_t grp_handle,
                                     pi_indirect_handle_t mbr_handle) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string ap_name(pi_p4info_act_prof_name_from_id(p4info, act_prof_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  try {
    client.c->bm_mt_act_prof_add_member_to_group(
        0, ap_name, mbr_handle, grp_handle);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid action profile (" << ap_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_grp_remove_mbr(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id,
                                        pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t grp_handle,
                                        pi_indirect_handle_t mbr_handle) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string ap_name(pi_p4info_act_prof_name_from_id(p4info, act_prof_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  try {
    client.c->bm_mt_act_prof_remove_member_from_group(
        0, ap_name, mbr_handle, grp_handle);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid action profile (" << ap_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

}
