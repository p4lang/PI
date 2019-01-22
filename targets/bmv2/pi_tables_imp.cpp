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

#include <algorithm>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include <cstring>

#include "action_helpers.h"
#include "common.h"
#include "conn_mgr.h"
#include "direct_res_spec.h"

namespace pibmv2 {

extern conn_mgr_t *conn_mgr_state;

}  // namespace pibmv2

namespace {

// We check which of pi_priority_t (PI type) and int32_t (bmv2 Thrift type) can
// fit the largest unsigned integer. If it is priority_t, BM_MAX_PRIORITY is set
// to the max value for an int32_t. If it is int32_t, BM_MAX_PRIORITY is set to
// the max value for a priority_t. BM_MAX_PRIORITY is then used as a pivot to
// invert priority values passed by PI.
static constexpr pi_priority_t BM_MAX_PRIORITY =
    (static_cast<uintmax_t>(std::numeric_limits<pi_priority_t>::max()) >=
     static_cast<uintmax_t>(std::numeric_limits<int32_t>::max())) ?
    static_cast<pi_priority_t>(std::numeric_limits<int32_t>::max()) :
    std::numeric_limits<pi_priority_t>::max();

class PriorityInverter {
 public:
  PriorityInverter() = delete;
  static int32_t pi_to_bm(pi_priority_t from) {
    assert(from <= BM_MAX_PRIORITY);
    return BM_MAX_PRIORITY - from;
  }
  static pi_priority_t bm_to_pi(int32_t from) {
    assert(from >= 0 && static_cast<uintmax_t>(from) <= BM_MAX_PRIORITY);
    return BM_MAX_PRIORITY - static_cast<pi_priority_t>(from);
  }
};

std::vector<BmMatchParam> build_key(pi_p4_id_t table_id,
                                    const pi_match_key_t *match_key,
                                    const pi_p4info_t *p4info,
                                    bool *requires_priority) {
  std::vector<BmMatchParam> key;
  *requires_priority = false;

  const char *mk_data = match_key->data;

  BmMatchParam param;
  BmMatchParamValid param_valid;
  BmMatchParamExact param_exact;
  BmMatchParamLPM param_lpm;
  BmMatchParamTernary param_ternary;
  BmMatchParamRange param_range;

  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, table_id);
  for (size_t i = 0; i < num_match_fields; i++) {
    auto finfo = pi_p4info_table_match_field_info(p4info, table_id, i);
    size_t f_bw = finfo->bitwidth;
    size_t nbytes = (f_bw + 7) / 8;
    uint32_t pLen;

    switch (finfo->match_type) {
      case PI_P4INFO_MATCH_TYPE_VALID:
        param_valid.key = (*mk_data != 0);
        mk_data++;
        param = BmMatchParam();
        param.type = BmMatchParamType::type::VALID;
        param.__set_valid(param_valid);  // does a copy of param_valid
        key.push_back(std::move(param));
        break;
      case PI_P4INFO_MATCH_TYPE_EXACT:
        param_exact.key = std::string(mk_data, nbytes);
        mk_data += nbytes;
        param = BmMatchParam();
        param.type = BmMatchParamType::type::EXACT;
        param.__set_exact(param_exact);  // does a copy of param_exact
        key.push_back(std::move(param));
        break;
      case PI_P4INFO_MATCH_TYPE_LPM:
        param_lpm.key = std::string(mk_data, nbytes);
        mk_data += nbytes;
        mk_data += retrieve_uint32(mk_data, &pLen);
        param_lpm.prefix_length = static_cast<int32_t>(pLen);
        param = BmMatchParam();
        param.type = BmMatchParamType::type::LPM;
        param.__set_lpm(param_lpm);  // does a copy of param_lpm
        key.push_back(std::move(param));
        break;
      case PI_P4INFO_MATCH_TYPE_TERNARY:
        param_ternary.key = std::string(mk_data, nbytes);
        mk_data += nbytes;
        param_ternary.mask = std::string(mk_data, nbytes);
        mk_data += nbytes;
        param = BmMatchParam();
        param.type = BmMatchParamType::type::TERNARY;
        param.__set_ternary(param_ternary);  // does a copy of param_ternary
        key.push_back(std::move(param));

        *requires_priority = true;
        break;
      case PI_P4INFO_MATCH_TYPE_RANGE:
        param_range.start = std::string(mk_data, nbytes);
        mk_data += nbytes;
        param_range.end_ = std::string(mk_data, nbytes);
        mk_data += nbytes;
        param = BmMatchParam();
        param.type = BmMatchParamType::type::RANGE;
        param.__set_range(param_range);  // does a copy of param_range
        key.push_back(std::move(param));

        *requires_priority = true;
        break;
      default:
        assert(0);
    }
  }

  return key;
}

void build_key_and_options(pi_p4_id_t table_id,
                           const pi_match_key_t *match_key,
                           const pi_p4info_t *p4info,
                           BmMatchParams *mkey, BmAddEntryOptions *options) {
  bool requires_priority = false;
  *mkey = build_key(table_id, match_key, p4info, &requires_priority);
  if (requires_priority)
    options->__set_priority(PriorityInverter::pi_to_bm(match_key->priority));
}


pi_entry_handle_t add_entry(const pi_p4info_t *p4info,
                            pi_dev_tgt_t dev_tgt,
                            const std::string &t_name,
                            const BmMatchParams &mkey,
                            const pi_action_data_t *adata,
                            const BmAddEntryOptions &options) {
  auto action_data = pibmv2::build_action_data(adata, p4info);
  pi_p4_id_t action_id = adata->action_id;
  std::string a_name(pi_p4info_action_name_from_id(p4info, action_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);

  return client.c->bm_mt_add_entry(
      0, t_name, mkey, a_name, action_data, options);
}

pi_entry_handle_t add_indirect_entry(const pi_p4info_t *p4info,
                                     pi_dev_tgt_t dev_tgt,
                                     const std::string &t_name,
                                     const BmMatchParams &mkey,
                                     pi_indirect_handle_t h,
                                     const BmAddEntryOptions &options) {
  (void) p4info;  // needed later?
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);

  bool is_grp_h = pibmv2::IndirectHMgr::is_grp_h(h);
  if (!is_grp_h) {
    return client.c->bm_mt_indirect_add_entry(
        0, t_name, mkey, h, options);
  } else {
    h = pibmv2::IndirectHMgr::clear_grp_h(h);
    return client.c->bm_mt_indirect_ws_add_entry(
        0, t_name, mkey, h, options);
  }
}

void set_default_entry(const pi_p4info_t *p4info,
                       pi_dev_tgt_t dev_tgt,
                       const std::string &t_name,
                       const pi_action_data_t *adata) {
  auto action_data = pibmv2::build_action_data(adata, p4info);
  pi_p4_id_t action_id = adata->action_id;
  std::string a_name(pi_p4info_action_name_from_id(p4info, action_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);

  return client.c->bm_mt_set_default_action(0, t_name, a_name, action_data);
}

void set_default_indirect_entry(const pi_p4info_t *p4info,
                                pi_dev_tgt_t dev_tgt,
                                const std::string &t_name,
                                pi_indirect_handle_t h) {
  (void) p4info;  // needed later?
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);

  bool is_grp_h = pibmv2::IndirectHMgr::is_grp_h(h);
  if (!is_grp_h) {
    return client.c->bm_mt_indirect_set_default_member(0, t_name, h);
  } else {
    h = pibmv2::IndirectHMgr::clear_grp_h(h);
    return client.c->bm_mt_indirect_ws_set_default_group(0, t_name, h);
  }
}

void modify_entry(const pi_p4info_t *p4info,
                  pi_dev_id_t dev_id,
                  const std::string &t_name,
                  pi_entry_handle_t entry_handle,
                  const pi_action_data_t *adata) {
  auto action_data = pibmv2::build_action_data(adata, p4info);
  pi_p4_id_t action_id = adata->action_id;
  std::string a_name(pi_p4info_action_name_from_id(p4info, action_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  return client.c->bm_mt_modify_entry(
      0, t_name, entry_handle, a_name, action_data);
}

void modify_indirect_entry(const pi_p4info_t *p4info,
                           pi_dev_id_t dev_id,
                           const std::string &t_name,
                           pi_entry_handle_t entry_handle,
                           pi_indirect_handle_t h) {
  (void) p4info;  // needed later?
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  bool is_grp_h = pibmv2::IndirectHMgr::is_grp_h(h);
  if (!is_grp_h) {
    return client.c->bm_mt_indirect_modify_entry(
        0, t_name, entry_handle, h);
  } else {
    h = pibmv2::IndirectHMgr::clear_grp_h(h);
    return client.c->bm_mt_indirect_ws_modify_entry(
        0, t_name, entry_handle, h);
  }
}

void retrieve_entry(const pi_p4info_t *p4info, const std::string &a_name,
                    const BmActionData &action_data,
                    pi_table_entry_t *table_entry) {
  const pi_p4_id_t action_id = pi_p4info_action_id_from_name(
      p4info, a_name.c_str());

  table_entry->entry_type = PI_ACTION_ENTRY_TYPE_DATA;

  const size_t adata_size = pi_p4info_action_data_size(p4info, action_id);

  // no alignment issue with new[]
  char *data_ = new char[sizeof(pi_action_data_t) + adata_size];
  pi_action_data_t *adata = reinterpret_cast<pi_action_data_t *>(data_);
  data_ += sizeof(pi_action_data_t);

  adata->p4info = p4info;
  adata->action_id = action_id;
  adata->data_size = adata_size;
  adata->data = data_;

  table_entry->entry.action_data = adata;

  data_ = pibmv2::dump_action_data(p4info, data_, action_id, action_data);
}

void retrieve_indirect_entry(const pi_p4info_t *p4info, int32_t h,
                             bool is_grp_h, pi_table_entry_t *table_entry) {
  (void) p4info;
  table_entry->entry_type = PI_ACTION_ENTRY_TYPE_INDIRECT;

  pi_indirect_handle_t indirect_handle = static_cast<pi_indirect_handle_t>(h);
  if (is_grp_h) {
    indirect_handle = pibmv2::IndirectHMgr::make_grp_h(indirect_handle);
  }

  table_entry->entry.indirect_handle = indirect_handle;
}

void set_direct_resources(const pi_p4info_t *p4info, pi_dev_id_t dev_id,
                          const std::string &t_name,
                          pi_entry_handle_t entry_handle,
                          const pi_direct_res_config_t *direct_res_config) {
  (void)p4info;
  if (!direct_res_config) return;
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);
  for (size_t i = 0; i < direct_res_config->num_configs; i++) {
    pi_direct_res_config_one_t *config = &direct_res_config->configs[i];
    pi_res_type_id_t type = PI_GET_TYPE_ID(config->res_id);
    switch (type) {
      case PI_DIRECT_COUNTER_ID:
        {
          auto value = pibmv2::convert_from_counter_data(
              reinterpret_cast<pi_counter_data_t *>(config->config));
          client.c->bm_mt_write_counter(0, t_name, entry_handle, value);
        }
        break;
      case PI_DIRECT_METER_ID:
        {
          auto rates = pibmv2::convert_from_meter_spec(
              reinterpret_cast<pi_meter_spec_t *>(config->config));
          client.c->bm_mt_set_meter_rates(0, t_name, entry_handle, rates);
        }
        break;
      default:  // TODO(antonin): what to do?
        assert(0);
    }
  }
}

pi_status_t retrieve_entry_wkey(pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                BmMtEntry *entry) {
  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  if (match_key->priority > BM_MAX_PRIORITY)
    return PI_STATUS_UNSUPPORTED_ENTRY_PRIORITY;
  BmMatchParams mkey;
  BmAddEntryOptions options;
  build_key_and_options(table_id, match_key, p4info, &mkey, &options);

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  try {
    client.c->bm_mt_get_entry_from_key(*entry, 0, t_name, mkey, options);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }
  return PI_STATUS_SUCCESS;
}

}  // namespace


extern "C" {

pi_status_t _pi_table_entry_add(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt,
                                pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                int overwrite,
                                pi_entry_handle_t *entry_handle) {
  (void) overwrite;  // TODO(antonin)
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  if (match_key->priority > BM_MAX_PRIORITY)
    return PI_STATUS_UNSUPPORTED_ENTRY_PRIORITY;
  BmMatchParams mkey;
  BmAddEntryOptions options;
  build_key_and_options(table_id, match_key, p4info, &mkey, &options);

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));

  // TODO(antonin): entry timeout
  try {
    switch (table_entry->entry_type) {
      case PI_ACTION_ENTRY_TYPE_DATA:
        *entry_handle = add_entry(p4info, dev_tgt, t_name, mkey,
                                  table_entry->entry.action_data, options);
        break;
      case PI_ACTION_ENTRY_TYPE_INDIRECT:
        *entry_handle = add_indirect_entry(p4info, dev_tgt, t_name, mkey,
                                           table_entry->entry.indirect_handle,
                                           options);
        break;
      default:
        assert(0);
    }
    // direct resources
    set_direct_resources(p4info, dev_tgt.dev_id, t_name, *entry_handle,
                         table_entry->direct_res_config);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_set(pi_session_handle_t session_handle,
                                         pi_dev_tgt_t dev_tgt,
                                         pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));

  try {
    if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_DATA) {
      const pi_action_data_t *adata = table_entry->entry.action_data;

      // TODO(antonin): equivalent for indirect?
      // TODO(antonin): move to common PI code?
      if (pi_p4info_table_has_const_default_action(p4info, table_id)) {
        bool has_mutable_action_params;
        auto default_action_id = pi_p4info_table_get_const_default_action(
            p4info, table_id, &has_mutable_action_params);
        if (default_action_id != adata->action_id)
          return PI_STATUS_CONST_DEFAULT_ACTION;
        (void)has_mutable_action_params;
      }

      set_default_entry(p4info, dev_tgt, t_name, adata);
    } else if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_INDIRECT) {
      set_default_indirect_entry(p4info, dev_tgt, t_name,
                                 table_entry->entry.indirect_handle);
    } else {
      assert(0);
    }
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_reset(pi_session_handle_t session_handle,
                                           pi_dev_tgt_t dev_tgt,
                                           pi_p4_id_t table_id) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));
  auto ap_id = pi_p4info_table_get_implementation(p4info, table_id);

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);

  try {
    if (ap_id == PI_INVALID_ID)
      client.c->bm_mt_reset_default_entry(0, t_name);
    else
      client.c->bm_mt_indirect_reset_default_entry(0, t_name);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_get(pi_session_handle_t session_handle,
                                         pi_dev_id_t dev_id,
                                         pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));

  BmActionEntry entry;
  try {
    conn_mgr_client(pibmv2::conn_mgr_state, dev_id).c->bm_mt_get_default_entry(
        entry, 0, t_name);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  switch (entry.action_type) {
    case BmActionEntryType::NONE:
      table_entry->entry_type = PI_ACTION_ENTRY_TYPE_NONE;
      break;
    case BmActionEntryType::ACTION_DATA:
      retrieve_entry(p4info, entry.action_name, entry.action_data, table_entry);
      break;
    case BmActionEntryType::MBR_HANDLE:
      retrieve_indirect_entry(p4info, entry.mbr_handle, false, table_entry);
      break;
    case BmActionEntryType::GRP_HANDLE:
      retrieve_indirect_entry(p4info, entry.grp_handle, true, table_entry);
      break;
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_done(pi_session_handle_t session_handle,
                                          pi_table_entry_t *table_entry) {
  (void) session_handle;

  if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_DATA) {
    pi_action_data_t *action_data = table_entry->entry.action_data;
    if (action_data) delete[] action_data;
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_p4_id_t table_id,
                                   pi_entry_handle_t entry_handle) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));
  auto ap_id = pi_p4info_table_get_implementation(p4info, table_id);

  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_id);

  try {
    if (ap_id == PI_INVALID_ID)
      client.c->bm_mt_delete_entry(0, t_name, entry_handle);
    else
      client.c->bm_mt_indirect_delete_entry(0, t_name, entry_handle);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

// for the _wkey functions (delete and modify), we first retrieve the handle,
// then call the "usual" method. We release the Thrift session lock in between
// the 2, which may not be ideal. This can be improved later if needed.

pi_status_t _pi_table_entry_delete_wkey(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                        const pi_match_key_t *match_key) {
  BmMtEntry entry;
  pi_status_t status = retrieve_entry_wkey(dev_id, table_id, match_key, &entry);
  if (status != PI_STATUS_SUCCESS) return status;
  return _pi_table_entry_delete(session_handle, dev_id, table_id,
                                entry.entry_handle);
}

pi_status_t _pi_table_entry_modify(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_p4_id_t table_id,
                                   pi_entry_handle_t entry_handle,
                                   const pi_table_entry_t *table_entry) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));

  try {
    if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_DATA) {
      modify_entry(p4info, dev_id, t_name, entry_handle,
                   table_entry->entry.action_data);
    } else if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_INDIRECT) {
      modify_indirect_entry(p4info, dev_id, t_name, entry_handle,
                            table_entry->entry.indirect_handle);
    } else {
      assert(0);
    }
    set_direct_resources(p4info, dev_id, t_name, entry_handle,
                         table_entry->direct_res_config);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_modify_wkey(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                        const pi_match_key_t *match_key,
                                        const pi_table_entry_t *table_entry) {
  BmMtEntry entry;
  pi_status_t status = retrieve_entry_wkey(dev_id, table_id, match_key, &entry);
  if (status != PI_STATUS_SUCCESS) return status;
  return _pi_table_entry_modify(session_handle, dev_id, table_id,
                                entry.entry_handle, table_entry);
}

pi_status_t _pi_table_entries_fetch(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id,
                                    pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res) {
  (void) session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;

  std::string t_name(pi_p4info_table_name_from_id(p4info, table_id));

  std::vector<BmMtEntry> entries;
  try {
    conn_mgr_client(pibmv2::conn_mgr_state, dev_id).c->bm_mt_get_entries(
        entries, 0, t_name);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  res->num_entries = entries.size();

  size_t data_size = 0u;

  data_size += entries.size() * sizeof(s_pi_entry_handle_t);
  // TODO(antonin): really needed of table type is enough?
  data_size += entries.size() * sizeof(s_pi_action_entry_type_t);
  data_size += entries.size() * sizeof(uint32_t);  // for priority
  data_size += entries.size() * sizeof(uint32_t);  // for properties
  data_size += entries.size() * sizeof(uint32_t);  // for direct resources

  res->mkey_nbytes = pi_p4info_table_match_key_size(p4info, table_id);
  data_size += entries.size() * res->mkey_nbytes;

  size_t num_actions;
  auto action_ids = pi_p4info_table_get_actions(p4info, table_id, &num_actions);
  auto action_map = pibmv2::ADataSize::compute_action_sizes(p4info, action_ids,
                                                            num_actions);

  for (const auto &e : entries) {
    switch (e.action_entry.action_type) {
      case BmActionEntryType::NONE:
        break;
      case BmActionEntryType::ACTION_DATA:
        data_size += action_map.at(e.action_entry.action_name).s;
        data_size += sizeof(s_pi_p4_id_t);  // action id
        data_size += sizeof(uint32_t);  // action data nbytes
        break;
      case BmActionEntryType::MBR_HANDLE:
      case BmActionEntryType::GRP_HANDLE:
        data_size += sizeof(s_pi_indirect_handle_t);
        break;
    }
  }

  char *data = new char[data_size];
  // in some cases, we do not use the whole buffer
  std::fill(data, data + data_size, 0);
  res->entries_size = data_size;
  res->entries = data;

  for (const auto &e : entries) {
    data += emit_entry_handle(data, e.entry_handle);
    const auto &options = e.options;
    // TODO(antonin): temporary hack; for match types which do not require a
    // priority, bmv2 actually returns -1 instead of not setting the field, but
    // the PI tends to expect 0, which is a problem for looking up entry state
    // in the PI software. A more robust solution may be to ignore this value in
    // the PI based on the key match type.
    if (options.__isset.priority && options.priority != -1) {
      data += emit_uint32(data, PriorityInverter::bm_to_pi(options.priority));
    } else {
      data += emit_uint32(data, 0);
    }
    for (const auto &p : e.match_key) {
      switch (p.type) {
        case BmMatchParamType::type::EXACT:
          std::memcpy(data, p.exact.key.data(), p.exact.key.size());
          data += p.exact.key.size();
          break;
        case BmMatchParamType::type::LPM:
          std::memcpy(data, p.lpm.key.data(), p.lpm.key.size());
          data += p.lpm.key.size();
          data += emit_uint32(data, p.lpm.prefix_length);
          break;
        case BmMatchParamType::type::TERNARY:
          std::memcpy(data, p.ternary.key.data(), p.ternary.key.size());
          data += p.ternary.key.size();
          std::memcpy(data, p.ternary.mask.data(), p.ternary.mask.size());
          data += p.ternary.mask.size();
          break;
        case BmMatchParamType::type::VALID:
          *data = p.valid.key;
          data++;
          break;
        case BmMatchParamType::type::RANGE:
          std::memcpy(data, p.range.start.data(), p.range.start.size());
          data += p.range.start.size();
          std::memcpy(data, p.range.end_.data(), p.range.end_.size());
          data += p.range.end_.size();
          break;
      }
    }

    const auto &action_entry = e.action_entry;

    switch (action_entry.action_type) {
      case BmActionEntryType::NONE:
        data += emit_action_entry_type(data, PI_ACTION_ENTRY_TYPE_NONE);
        break;
      case BmActionEntryType::ACTION_DATA:
        {
          data += emit_action_entry_type(data, PI_ACTION_ENTRY_TYPE_DATA);
          const auto &adata_size = action_map.at(action_entry.action_name);
          data += emit_p4_id(data, adata_size.id);
          data += emit_uint32(data, adata_size.s);
          data = pibmv2::dump_action_data(p4info, data, adata_size.id,
                                          action_entry.action_data);
        }
        break;
      case BmActionEntryType::MBR_HANDLE:
        {
          data += emit_action_entry_type(data, PI_ACTION_ENTRY_TYPE_INDIRECT);
          auto indirect_handle =
              static_cast<pi_indirect_handle_t>(action_entry.mbr_handle);
          data += emit_indirect_handle(data, indirect_handle);
        }
        break;
      case BmActionEntryType::GRP_HANDLE:
        {
          data += emit_action_entry_type(data, PI_ACTION_ENTRY_TYPE_INDIRECT);
          auto indirect_handle =
              static_cast<pi_indirect_handle_t>(action_entry.mbr_handle);
          indirect_handle = pibmv2::IndirectHMgr::make_grp_h(indirect_handle);
          data += emit_indirect_handle(data, indirect_handle);
        }
        break;
    }

    data += emit_uint32(data, 0);  // properties
    data += emit_uint32(data, 0);  // TODO(antonin): direct resources
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entries_fetch_done(pi_session_handle_t session_handle,
                                         pi_table_fetch_res_t *res) {
  (void) session_handle;

  delete[] res->entries;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_idle_timeout_config_set(
    pi_session_handle_t session_handle,
    pi_dev_id_t dev_id,
    pi_p4_id_t table_id,
    const pi_idle_timeout_config_t *config) {
  (void)session_handle;
  (void)dev_id;
  (void)table_id;
  (void)config;
  return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_table_entry_get_remaining_ttl(
    pi_session_handle_t session_handle, pi_dev_id_t dev_id, pi_p4_id_t table_id,
    pi_entry_handle_t entry_handle, uint64_t *ttl_ns) {
  (void)session_handle;
  (void)dev_id;
  (void)table_id;
  (void)entry_handle;
  (void)ttl_ns;
  return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

}
