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
  res_->idx = 0;
  res_->curr = 0;
  *res = res_;
  return _pi_table_entries_fetch(dev_id, table_id, res_);
}

pi_status_t pi_table_entries_fetch_done(pi_table_fetch_res_t *res) {
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
  *entry_handle = (pi_entry_handle_t) res->entries[res->curr++].v;
  entry->match_key = res->entries + res->curr;
  res->curr += res->num_match_fields;
  pi_table_entry_t *t_entry = &entry->entry;
  t_entry->action_id = res->entries[res->curr].v1;
  size_t action_data_size = res->entries[res->curr++].v2;
  t_entry->action_data = res->entries + res->curr;
  res->curr += action_data_size;
  t_entry->entry_properties = res->properties + res->idx;
  return res->idx++;
}
