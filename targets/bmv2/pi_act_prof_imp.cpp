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
#include <PI/int/serialize.h>
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

  grp_handle = pibmv2::IndirectHMgr::clear_grp_h(grp_handle);

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

  grp_handle = pibmv2::IndirectHMgr::clear_grp_h(grp_handle);

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

  grp_handle = pibmv2::IndirectHMgr::clear_grp_h(grp_handle);

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
  return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_act_prof_entries_fetch(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id,
                                       pi_p4_id_t act_prof_id,
                                       pi_act_prof_fetch_res_t *res) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string ap_name(pi_p4info_act_prof_name_from_id(p4info, act_prof_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  std::vector<BmMtActProfMember> members;
  std::vector<BmMtActProfGroup> groups;
  try {
    client.c->bm_mt_act_prof_get_members(members, 0, ap_name);
    client.c->bm_mt_act_prof_get_groups(groups, 0, ap_name);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid action profile (" << ap_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  // members
  {
    res->num_members = members.size();

    size_t data_size = 0;
    data_size += members.size() * sizeof(s_pi_indirect_handle_t);
    // action id and action data nbytes
    data_size += members.size() * (sizeof(s_pi_p4_id_t) + sizeof(uint32_t));
    size_t num_actions;
    auto action_ids = pi_p4info_act_prof_get_actions(p4info, act_prof_id,
                                                     &num_actions);
    auto action_map = pibmv2::ADataSize::compute_action_sizes(
        p4info, action_ids, num_actions);
    for (const auto &mbr : members)
      data_size += action_map.at(mbr.action_name).s;

    char *data = new char[data_size];
    res->entries_members_size = data_size;
    res->entries_members = data;

    for (const auto &mbr : members) {
      data += emit_indirect_handle(data, mbr.mbr_handle);
      const auto &adata_size = action_map.at(mbr.action_name);
      data += emit_p4_id(data, adata_size.id);
      data += emit_uint32(data, adata_size.s);
      data = pibmv2::dump_action_data(p4info, data, adata_size.id,
                                      mbr.action_data);
    }
  }

  // groups
  {
    res->num_groups = groups.size();

    size_t data_size = 0;
    size_t num_member_handles = 0;
    data_size += groups.size() * sizeof(s_pi_indirect_handle_t);
    // number of members + offset in member handles list
    data_size += groups.size() * 2 * sizeof(uint32_t);
    for (const auto &grp : groups) num_member_handles += grp.mbr_handles.size();

    char *data = new char[data_size];
    res->entries_groups_size = data_size;
    res->entries_groups = data;
    res->num_cumulated_mbr_handles = num_member_handles;
    res->mbr_handles = new pi_indirect_handle_t[num_member_handles];

    size_t handle_offset = 0;
    for (const auto &grp : groups) {
      data += emit_indirect_handle(
          data, pibmv2::IndirectHMgr::make_grp_h(grp.grp_handle));
      const auto num_mbrs = grp.mbr_handles.size();
      data += emit_uint32(data, num_mbrs);
      data += emit_uint32(data, handle_offset);
      for (const auto mbr_h : grp.mbr_handles)
        res->mbr_handles[handle_offset++] = mbr_h;
    }
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_act_prof_entries_fetch_done(pi_session_handle_t session_handle,
                                            pi_act_prof_fetch_res_t *res) {
  (void)session_handle;

  delete[] res->entries_members;
  delete[] res->entries_groups;
  delete[] res->mbr_handles;
  return PI_STATUS_SUCCESS;
}

int _pi_act_prof_api_support(pi_dev_id_t dev_id) {
  (void)dev_id;
  return PI_ACT_PROF_API_SUPPORT_GRP_ADD_AND_REMOVE_MBR;
}

}
