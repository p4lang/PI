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

#ifndef PI_SRC_TARGET_PI_TABLES_IMP_H_
#define PI_SRC_TARGET_PI_TABLES_IMP_H_

pi_status_t _pi_table_entry_add(const pi_dev_tgt_t dev_tgt,
                                const pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                const int overwrite,
                                pi_entry_handle_t *entry_handle);

pi_status_t _pi_table_default_action_set(const pi_dev_tgt_t dev_tgt,
                                         const pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry);

pi_status_t _pi_table_default_action_get(const pi_dev_tgt_t dev_tgt,
                                         const pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry);

pi_status_t _pi_table_entry_delete(const uint16_t dev_id,
                                   const pi_p4_id_t table_id,
                                   const pi_entry_handle_t entry_handle);

pi_status_t _pi_table_entry_modify(const uint16_t dev_id,
                                   const pi_p4_id_t table_id,
                                   const pi_entry_handle_t entry_handle,
                                   const pi_table_entry_t *table_entry);

pi_status_t _pi_table_retrieve(const uint16_t dev_id,
                               const pi_p4_id_t table_id,
                               pi_table_retrieve_res_t **res);

#endif  // PI_SRC_TARGET_PI_TABLES_IMP_H_
