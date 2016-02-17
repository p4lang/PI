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

pi_status_t pi_table_retrieve(const uint16_t dev_id,
                              const pi_p4_id_t table_id,
                              pi_table_retrieve_res_t **res) {
  return _pi_table_retrieve(dev_id, table_id, res);
}
