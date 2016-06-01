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

#include "PI/pi_tables.h"
#include "target/pi_tables_imp.h"
#include "pi_int.h"
#include "utils/serialize.h"

#include <stdlib.h>

void pi_entry_properties_clear(pi_entry_properties_t *properties) {
  (void) properties;
}

void pi_entry_properties_set(pi_entry_properties_t *properties,
                             const pi_entry_property_type_t property_type,
                             const pi_value_t *property_value) {
  (void) properties; (void) property_type; (void) property_value;
}

pi_status_t pi_table_entry_add(const pi_dev_tgt_t dev_tgt,
                               const pi_p4_id_t table_id,
                               const pi_match_key_t *match_key,
                               const pi_table_entry_t *table_entry,
                               const int overwrite,
                               pi_entry_handle_t *entry_handle) {
  return _pi_table_entry_add(dev_tgt, table_id, match_key, table_entry,
                             overwrite, entry_handle);
}

pi_status_t pi_table_default_action_set(const pi_dev_tgt_t dev_tgt,
                                        const pi_p4_id_t table_id,
                                        const pi_table_entry_t *table_entry) {
  return _pi_table_default_action_set(dev_tgt, table_id, table_entry);
}

pi_status_t pi_table_default_action_get(const pi_dev_tgt_t dev_tgt,
                                        const pi_p4_id_t table_id,
                                        pi_table_entry_t *table_entry) {
  return _pi_table_default_action_get(dev_tgt, table_id, table_entry);
}

pi_status_t pi_table_entry_delete(const uint16_t dev_id,
                                  const pi_p4_id_t table_id,
                                  const pi_entry_handle_t entry_handle) {
  return _pi_table_entry_delete(dev_id, table_id, entry_handle);
}

pi_status_t pi_table_entry_modify(const uint16_t dev_id,
                                  const pi_p4_id_t table_id,
                                  const pi_entry_handle_t entry_handle,
                                  const pi_table_entry_t *table_entry) {
  return _pi_table_entry_modify(dev_id, table_id, entry_handle, table_entry);
}

pi_status_t pi_table_entries_fetch(const pi_dev_id_t dev_id,
                                   const pi_p4_id_t table_id,
                                   pi_table_fetch_res_t **res) {
  pi_table_fetch_res_t *res_ = malloc(sizeof(pi_table_fetch_res_t));
  res_->p4info = pi_get_device_p4info(dev_id);
  res_->table_id = table_id;
  res_->idx = 0;
  res_->curr = 0;
  // TODO(antonin): use contiguous memory
  res_->match_keys = malloc(res_->num_entries * sizeof(pi_match_key_t));
  res_->action_datas = malloc(res_->num_entries * sizeof(pi_action_data_t));
  pi_status_t status = _pi_table_entries_fetch(dev_id, table_id, res_);
  *res = res_;
  return status;
}

pi_status_t pi_table_entries_fetch_done(pi_table_fetch_res_t *res) {
  assert(res->match_keys);
  free(res->match_keys);
  assert(res->action_datas);
  free(res->action_datas);
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

  res->curr += retrieve_uint64(res->entries + res->curr, entry_handle);

  entry->match_key = &res->match_keys[res->idx];
  entry->match_key->data = res->entries + res->curr;
  entry->match_key->p4info = res->p4info;
  res->curr += res->mkey_nbytes;

  pi_table_entry_t *t_entry = &entry->entry;
  res->curr += retrieve_uint32(res->entries + res->curr, &t_entry->action_id);
  uint32_t nbytes;
  res->curr += retrieve_uint32(res->entries + res->curr, &nbytes);
  t_entry->action_data = &res->action_datas[res->idx];
  t_entry->action_data->data = res->entries + res->curr;
  t_entry->action_data->p4info = res->p4info;
  res->curr += nbytes;
  t_entry->entry_properties = res->properties + res->idx;
  return res->idx++;
}
