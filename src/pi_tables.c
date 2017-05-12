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
#include <PI/pi.h>
#include <PI/pi_tables.h>
#include <PI/target/pi_tables_imp.h>

#include <stdlib.h>
#include <string.h>

void pi_entry_properties_clear(pi_entry_properties_t *properties) {
  memset(properties, 0, sizeof(*properties));
}

pi_status_t pi_entry_properties_set(pi_entry_properties_t *properties,
                                    pi_entry_property_type_t property_type,
                                    uint32_t property_value) {
  /* const pi_value_t *property_value) { */
  switch (property_type) {
    case PI_ENTRY_PROPERTY_TYPE_TTL:
      properties->ttl = property_value;
      break;
    default:
      return PI_STATUS_INVALID_ENTRY_PROPERTY;
  }
  assert(property_type <= 8 * sizeof(properties->valid_properties));
  properties->valid_properties |= (1 << property_type);
  // TODO(antonin): return different code if the property was set previously
  return PI_STATUS_SUCCESS;
}

bool pi_entry_properties_is_set(const pi_entry_properties_t *properties,
                                pi_entry_property_type_t property_type) {
  if (!properties) return false;
  if (property_type >= PI_ENTRY_PROPERTY_TYPE_END) return false;
  return properties->valid_properties & (1 << property_type);
}

static bool check_direct_res_config(
    const pi_p4info_t *p4info, pi_p4_id_t table_id,
    const pi_direct_res_config_t *direct_res_config) {
  if (!direct_res_config) return true;
  for (size_t i = 0; i < direct_res_config->num_configs; i++) {
    pi_p4_id_t res_id = direct_res_config->configs[0].res_id;
    if (!pi_p4info_table_is_direct_resource_of(p4info, table_id, res_id))
      return false;
  }
  return true;
}

static pi_status_t check_table_entry(const pi_p4info_t *p4info,
                                     pi_p4_id_t table_id,
                                     const pi_table_entry_t *t_entry) {
  if (!check_direct_res_config(p4info, table_id, t_entry->direct_res_config))
    return PI_STATUS_NOT_A_DIRECT_RES_OF_TABLE;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_table_entry_add(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                               const pi_match_key_t *match_key,
                               const pi_table_entry_t *table_entry,
                               int overwrite, pi_entry_handle_t *entry_handle) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  pi_status_t status = check_table_entry(p4info, table_id, table_entry);
  if (status != PI_STATUS_SUCCESS) return status;

  return _pi_table_entry_add(session_handle, dev_tgt, table_id, match_key,
                             table_entry, overwrite, entry_handle);
}

pi_status_t pi_table_default_action_set(pi_session_handle_t session_handle,
                                        pi_dev_tgt_t dev_tgt,
                                        pi_p4_id_t table_id,
                                        const pi_table_entry_t *table_entry) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  pi_status_t status = check_table_entry(p4info, table_id, table_entry);
  if (status != PI_STATUS_SUCCESS) return status;

  return _pi_table_default_action_set(session_handle, dev_tgt, table_id,
                                      table_entry);
}

pi_status_t pi_table_default_action_get(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                        pi_table_entry_t *table_entry) {
  pi_status_t status;
  status = _pi_table_default_action_get(session_handle, dev_id, table_id,
                                        table_entry);
  if (status != PI_STATUS_SUCCESS) return status;

  // TODO(antonin): improve
  if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_DATA) {
    pi_action_data_t *action_data = table_entry->entry.action_data;
    action_data->p4info = pi_get_device_p4info(dev_id);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t pi_table_default_action_done(pi_session_handle_t session_handle,
                                         pi_table_entry_t *table_entry) {
  return _pi_table_default_action_done(session_handle, table_entry);
}

pi_status_t pi_table_entry_delete(pi_session_handle_t session_handle,
                                  pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                  pi_entry_handle_t entry_handle) {
  return _pi_table_entry_delete(session_handle, dev_id, table_id, entry_handle);
}

pi_status_t pi_table_entry_delete_wkey(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                       const pi_match_key_t *match_key) {
  return _pi_table_entry_delete_wkey(session_handle, dev_id, table_id,
                                     match_key);
}

pi_status_t pi_table_entry_modify(pi_session_handle_t session_handle,
                                  pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                  pi_entry_handle_t entry_handle,
                                  const pi_table_entry_t *table_entry) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  pi_status_t status = check_table_entry(p4info, table_id, table_entry);
  if (status != PI_STATUS_SUCCESS) return status;

  return _pi_table_entry_modify(session_handle, dev_id, table_id, entry_handle,
                                table_entry);
}

pi_status_t pi_table_entry_modify_wkey(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                       const pi_match_key_t *match_key,
                                       const pi_table_entry_t *table_entry) {
  return _pi_table_entry_modify_wkey(session_handle, dev_id, table_id,
                                     match_key, table_entry);
}

pi_status_t pi_table_entries_fetch(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                   pi_table_fetch_res_t **res) {
  pi_table_fetch_res_t *res_ = malloc(sizeof(pi_table_fetch_res_t));
  pi_status_t status =
      _pi_table_entries_fetch(session_handle, dev_id, table_id, res_);
  res_->p4info = pi_get_device_p4info(dev_id);
  res_->table_id = table_id;
  res_->idx = 0;
  res_->curr = 0;
  // TODO(antonin): use contiguous memory
  res_->match_keys = malloc(res_->num_entries * sizeof(pi_match_key_t));
  res_->action_datas = malloc(res_->num_entries * sizeof(pi_action_data_t));
  res_->properties = malloc(res_->num_entries * sizeof(pi_entry_properties_t));
  *res = res_;
  return status;
}

pi_status_t pi_table_entries_fetch_done(pi_session_handle_t session_handle,
                                        pi_table_fetch_res_t *res) {
  pi_status_t status = _pi_table_entries_fetch_done(session_handle, res);
  if (status != PI_STATUS_SUCCESS) return status;

  assert(res->match_keys);
  free(res->match_keys);
  assert(res->action_datas);
  free(res->action_datas);
  assert(res->properties);
  free(res->properties);
  free(res);
  return PI_STATUS_SUCCESS;
}

size_t pi_table_entries_num(pi_table_fetch_res_t *res) {
  return res->num_entries;
}

size_t pi_table_entries_next(pi_table_fetch_res_t *res,
                             pi_table_ma_entry_t *entry,
                             pi_entry_handle_t *entry_handle) {
  if (res->idx == res->num_entries) return res->idx;

  res->curr += retrieve_entry_handle(res->entries + res->curr, entry_handle);

  entry->match_key = &res->match_keys[res->idx];
  entry->match_key->p4info = res->p4info;
  entry->match_key->table_id = res->table_id;
  res->curr +=
      retrieve_uint32(res->entries + res->curr, &entry->match_key->priority);
  entry->match_key->data_size = res->mkey_nbytes;
  entry->match_key->data = res->entries + res->curr;
  res->curr += res->mkey_nbytes;

  pi_table_entry_t *t_entry = &entry->entry;
  res->curr += retrieve_action_entry_type(res->entries + res->curr,
                                          &t_entry->entry_type);
  switch (t_entry->entry_type) {
    case PI_ACTION_ENTRY_TYPE_NONE:  // does it even make sense?
      break;
    case PI_ACTION_ENTRY_TYPE_DATA: {
      pi_p4_id_t action_id;
      res->curr += retrieve_p4_id(res->entries + res->curr, &action_id);
      uint32_t nbytes;
      res->curr += retrieve_uint32(res->entries + res->curr, &nbytes);
      pi_action_data_t *action_data = &res->action_datas[res->idx];
      t_entry->entry.action_data = action_data;
      action_data->p4info = res->p4info;
      action_data->action_id = action_id;
      action_data->data_size = nbytes;
      action_data->data = res->entries + res->curr;
      res->curr += nbytes;
    } break;
    case PI_ACTION_ENTRY_TYPE_INDIRECT: {
      pi_indirect_handle_t indirect_handle;
      res->curr +=
          retrieve_indirect_handle(res->entries + res->curr, &indirect_handle);
      t_entry->entry.indirect_handle = indirect_handle;
    } break;
  }

  pi_entry_properties_t *properties = res->properties + res->idx;
  t_entry->entry_properties = properties;
  res->curr +=
      retrieve_uint32(res->entries + res->curr, &properties->valid_properties);
  if (properties->valid_properties & (1 << PI_ENTRY_PROPERTY_TYPE_TTL)) {
    res->curr += retrieve_uint32(res->entries + res->curr, &properties->ttl);
  }

  return res->idx++;
}
