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

#include "PI/p4info/tables.h"

pi_p4_id_t pi_p4info_table_id_from_name(const char *name) {
  (void) name;
  return 0;
}

const char *pi_p4info_table_name_from_id(pi_p4_id_t table_id) {
  (void) table_id;
  return NULL;
}

size_t pi_p4info_table_num_match_fields(pi_p4_id_t table_id) {
  (void) table_id;
  return 0;
}

const pi_p4_id_t *pi_p4info_table_get_match_fields(pi_p4_id_t table_id,
                                                   size_t *num_match_fields) {
  (void) table_id; (void) num_match_fields;
  return NULL;
}

bool pi_p4info_table_is_match_field_of(pi_p4_id_t table_id,
                                       pi_p4_id_t field_id) {
  (void) table_id; (void) field_id;
  return false;
}

size_t pi_p4info_table_num_actions(pi_p4_id_t table_id) {
  (void) table_id;
  return 0;
}

bool pi_p4info_table_is_action_of(pi_p4_id_t table_id, pi_p4_id_t action_id) {
  (void) table_id; (void) action_id;
  return false;
}

const pi_p4_id_t *pi_p4info_table_get_actions(pi_p4_id_t table_id,
                                              size_t *num_actions) {
  (void) table_id; (void) num_actions;
  return NULL;
}
