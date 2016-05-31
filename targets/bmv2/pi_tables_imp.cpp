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

#include "conn_mgr.h"
#include "common.h"

#include "PI/pi.h"
#include "PI/pi_p4info.h"
#include "pi_int.h"
#include "utils/serialize.h"

#include <string>
#include <vector>

extern conn_mgr_t *conn_mgr_state;
extern int *my_devices;

namespace {

std::vector<BmMatchParam> build_key(pi_p4_id_t table_id,
                                    const pi_match_key_t *match_key,
                                    const pi_p4info_t *p4info) {
  static thread_local std::vector<BmMatchParam> key;
  key.clear();

  BmMatchParam param;
  BmMatchParamValid param_valid;
  BmMatchParamExact param_exact;
  BmMatchParamLPM param_lpm;
  BmMatchParamTernary param_ternary;

  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, table_id);
  for (size_t i = 0; i < num_match_fields; i++) {
    pi_p4info_match_field_info_t finfo;
    pi_p4info_table_match_field_info(p4info, table_id, i, &finfo);
    size_t f_bw = finfo.bitwidth;
    size_t nbytes = (f_bw + 7) / 8;
    uint32_t pLen;

    switch (finfo.match_type) {
      case PI_P4INFO_MATCH_TYPE_VALID:
        param_valid.key = (*match_key != 0);
        match_key++;
        param = BmMatchParam();
        param.type = BmMatchParamType::type::VALID;
        param.__set_valid(param_valid);  // does a copy of param_valid
        key.push_back(std::move(param));
        break;
      case PI_P4INFO_MATCH_TYPE_EXACT:
        param_exact.key = std::string(match_key, nbytes);
        match_key += nbytes;
        param = BmMatchParam();
        param.type = BmMatchParamType::type::EXACT;
        param.__set_exact(param_exact);  // does a copy of param_exact
        key.push_back(std::move(param));
        break;
      case PI_P4INFO_MATCH_TYPE_LPM:
        param_lpm.key = std::string(match_key, nbytes);
        match_key += nbytes;
        match_key += retrieve_uint32(match_key, &pLen);
        param_lpm.prefix_length = static_cast<int32_t>(pLen);
        param = BmMatchParam();
        param.type = BmMatchParamType::type::LPM;
        param.__set_lpm(param_lpm);  // does a copy of param_lpm
        key.push_back(std::move(param));
        break;
      case PI_P4INFO_MATCH_TYPE_TERNARY:
        param_ternary.key = std::string(match_key, nbytes);
        match_key += nbytes;
        param_ternary.mask = std::string(match_key, nbytes);
        match_key += nbytes;
        param = BmMatchParam();
        param.type = BmMatchParamType::type::TERNARY;
        param.__set_ternary(param_ternary);  // does a copy of param_ternary
        key.push_back(std::move(param));
        break;
      default:
        assert(0);
    }
  }

  return key;
}

std::vector<std::string> build_action_data(const pi_table_entry_t *table_entry,
                                           const pi_p4info_t *p4info) {
  static thread_local std::vector<std::string> data;
  data.clear();

  pi_p4_id_t action_id = table_entry->action_id;
  const pi_action_data_t *action_data = table_entry->action_data;
  assert(action_data);

  size_t num_params;
  const pi_p4_id_t *param_ids = pi_p4info_action_get_params(p4info, action_id,
                                                            &num_params);
  for (size_t i = 0; i < num_params; i++) {
    pi_p4_id_t p_id = param_ids[i];
    size_t p_bw = pi_p4info_action_param_bitwidth(p4info, p_id);
    size_t nbytes = (p_bw + 7) / 8;
    data.push_back(std::string(action_data, nbytes));
    action_data += nbytes;
  }

  return data;
}

// void fetch_insert_data(const std::string &data,
//                        std::vector<_compact_v_t> *cvs,
//                        std::vector<char> *oversize) {
//   _compact_v_t cv;
//   if (data.size() <= 8 * sizeof(cv.bytes)) {
//     std::memcpy(&cv.bytes, data.data(), data.size());
//     cvs->push_back(cv);
//   } else {
//   }
// }

}  // namespace

extern "C" {

pi_status_t _pi_table_entry_add(const pi_dev_tgt_t dev_tgt,
                                const pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                const int overwrite,
                                pi_entry_handle_t *entry_handle) {
  (void) overwrite;  // TODO

  device_info_t *d_info = get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::vector<BmMatchParam> mkey = build_key(table_id, match_key, p4info);
  std::vector<std::string> action_data = build_action_data(table_entry, p4info);
  // TODO: priority for ternary
  BmAddEntryOptions options;

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));
  std::string a_name(
      pi_p4info_action_name_from_id(p4info, table_entry->action_id));

  auto client = conn_mgr_client(conn_mgr_state, dev_tgt.dev_id);

  try {
    *entry_handle = client.c->bm_mt_add_entry(
        0, t_name, mkey, a_name, action_data, options);
    // TODO: entry timeout
    // TODO: direct meters
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << "${t_name}" << ") operation ("
              << ito.code << "): " << what << std::endl;
    return PI_STATUS_INVALID_TABLE_OPERATION;
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_set(const pi_dev_tgt_t dev_tgt,
                                         const pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry) {
  device_info_t *d_info = get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  if (pi_p4info_table_has_const_default_action(p4info, table_id)) {
    const pi_p4_id_t default_action_id =
        pi_p4info_table_get_const_default_action(p4info, table_id);
    if (default_action_id != table_entry->action_id)
      return PI_STATUS_CONST_DEFAULT_ACTION;
  }

  std::vector<std::string> action_data = build_action_data(table_entry, p4info);

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));
  std::string a_name(
      pi_p4info_action_name_from_id(p4info, table_entry->action_id));

  auto client = conn_mgr_client(conn_mgr_state, dev_tgt.dev_id);

  try {
    client.c->bm_mt_set_default_action(0, t_name, a_name, action_data);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << "${t_name}" << ") operation ("
              << ito.code << "): " << what << std::endl;
    return PI_STATUS_INVALID_TABLE_OPERATION;
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_get(const pi_dev_tgt_t dev_tgt,
                                         const pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry) {
  (void) dev_tgt; (void) table_id; (void) table_entry;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_delete(const pi_dev_id_t dev_id,
                                   const pi_p4_id_t table_id,
                                   const pi_entry_handle_t entry_handle) {
  device_info_t *d_info = get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));

  auto client = conn_mgr_client(conn_mgr_state, dev_id);

  try {
    client.c->bm_mt_delete_entry(0, t_name, entry_handle);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << "${t_name}" << ") operation ("
              << ito.code << "): " << what << std::endl;
    return PI_STATUS_INVALID_TABLE_OPERATION;
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_modify(const pi_dev_id_t dev_id,
                                   const pi_p4_id_t table_id,
                                   const pi_entry_handle_t entry_handle,
                                   const pi_table_entry_t *table_entry) {
  device_info_t *d_info = get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::vector<std::string> action_data = build_action_data(table_entry, p4info);

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));
  std::string a_name(
      pi_p4info_action_name_from_id(p4info, table_entry->action_id));

  auto client = conn_mgr_client(conn_mgr_state, dev_id);

  try {
    client.c->bm_mt_modify_entry(0, t_name, entry_handle, a_name, action_data);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << "${t_name}" << ") operation ("
              << ito.code << "): " << what << std::endl;
    return PI_STATUS_INVALID_TABLE_OPERATION;
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entries_fetch(const pi_dev_id_t dev_id,
                                    const pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res) {
  device_info_t *d_info = get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));

  (void) dev_id; (void) table_id; (void) res;
  std::vector<BmMtEntry> entries;
  try {
    conn_mgr_client(conn_mgr_state, dev_id).c->bm_mt_get_entries(
        entries, 0, t_name);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << "${t_name}" << ") operation ("
              << ito.code << "): " << what << std::endl;
    return PI_STATUS_INVALID_TABLE_OPERATION;
  }

  // size_t n_cvs = 0u;
  // size_t extra_data = 0u;
  // for (const auto &e : entries) {
  //   n_cvs += e.action_entry.action_data.size
  // }

  // res->num_entries = entries.size();
  // std::vector<_compact_v_t> cvs;
  // _compact_v_t cv;
  // std::vector<char> extra_data;
  // for (auto &e : entries) {
  //   cv.v = (uint64_t) e.entry_handle;
  //   cvs.push_back(cv);
  //   for (auto p : e.match_key) {
  //     switch(p.type) {
  //       case BmMatchParamType::type::EXACT:
  //         break;
  //       case BmMatchParamType::type::LPM:
  //         break;
  //       case BmMatchParamType::type::TERNARY:
  //         break;
  //       case BmMatchParamType::type::VALID:
  //         break;
  //     }
  //   }
  // }

  return PI_STATUS_SUCCESS;
}

}
