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

#include <string>
#include <vector>

extern conn_mgr_t *conn_mgr_state;
extern int *my_devices;

namespace {

const char *bytes_from_compact_v(const _compact_v_t *v, size_t bitwidth) {
  return (bitwidth > 8 * sizeof(v->bytes)) ? v->more_bytes : &v->bytes[0];
}

std::vector<BmMatchParam> build_key(pi_p4_id_t table_id,
                                    const pi_match_key_t *match_key,
                                    const pi_p4info_t *p4info) {
  static thread_local std::vector<BmMatchParam> key;
  key.clear();

  assert(table_id == match_key->table_id);

  BmMatchParam param;
  BmMatchParamValid param_valid;
  BmMatchParamExact param_exact;
  BmMatchParamLPM param_lpm;
  BmMatchParamTernary param_ternary;

  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, table_id);
  const _compact_v_t *curr_v = match_key->data;
  for (size_t i = 0; i < num_match_fields; i++) {
    pi_p4info_match_field_info_t finfo;
    pi_p4info_table_match_field_info(p4info, table_id, i, &finfo);
    size_t f_bw = finfo.bitwidth;
    size_t nbytes = (f_bw + 7) / 8;
    const char *src;

    switch (finfo.match_type) {
      case PI_P4INFO_MATCH_TYPE_VALID:
        param_valid.key = (curr_v->v != 0);
        curr_v++;
        param = BmMatchParam();
        param.type = BmMatchParamType::type::VALID;
        param.__set_valid(param_valid);  // does a copy of param_valid
        key.push_back(std::move(param));
        break;
      case PI_P4INFO_MATCH_TYPE_EXACT:
        src = bytes_from_compact_v(curr_v, f_bw);
        curr_v++;
        param_exact.key = std::string(src, nbytes);
        param = BmMatchParam();
        param.type = BmMatchParamType::type::EXACT;
        param.__set_exact(param_exact);  // does a copy of param_exact
        key.push_back(std::move(param));
        break;
      case PI_P4INFO_MATCH_TYPE_LPM:
        src = bytes_from_compact_v(curr_v, f_bw);
        curr_v++;
        param_lpm.key = std::string(src, nbytes);
        param_lpm.prefix_length = curr_v->v;
        curr_v++;
        param = BmMatchParam();
        param.type = BmMatchParamType::type::LPM;
        param.__set_lpm(param_lpm);  // does a copy of param_lpm
        key.push_back(std::move(param));
        break;
      case PI_P4INFO_MATCH_TYPE_TERNARY:
        src = bytes_from_compact_v(curr_v, f_bw);
        curr_v++;
        param_ternary.key = std::string(src, nbytes);
        src = bytes_from_compact_v(curr_v, f_bw);
        curr_v++;
        param_ternary.mask = std::string(src, nbytes);
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
  assert(action_id == action_data->action_id);

  size_t num_params;
  const pi_p4_id_t *param_ids = pi_p4info_action_get_params(p4info, action_id,
                                                            &num_params);
  const _compact_v_t *curr_v = action_data->data;
  for (size_t i = 0; i < num_params; i++) {
    pi_p4_id_t p_id = param_ids[i];
    size_t p_bw = pi_p4info_action_param_bitwidth(p4info, p_id);
    size_t nbytes = (p_bw + 7) / 8;
    const char *src = bytes_from_compact_v(curr_v, p_bw);
    curr_v++;
    data.push_back(std::string(src, nbytes));
  }

  return data;
}

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
  (void) dev_tgt; (void) table_id; (void) table_entry;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_get(const pi_dev_tgt_t dev_tgt,
                                         const pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry) {
  (void) dev_tgt; (void) table_id; (void) table_entry;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_delete(const uint16_t dev_id,
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

pi_status_t _pi_table_entry_modify(const uint16_t dev_id,
                                   const pi_p4_id_t table_id,
                                   const pi_entry_handle_t entry_handle,
                                   const pi_table_entry_t *table_entry) {
  (void) dev_id; (void) table_id; (void) entry_handle; (void) table_entry;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_retrieve(const uint16_t dev_id,
                               const pi_p4_id_t table_id,
                               pi_table_retrieve_res_t **res) {
  (void) dev_id; (void) table_id; (void) res;
  return PI_STATUS_SUCCESS;
}

}
