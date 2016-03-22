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
#include "p4info/p4info_struct.h"

#include <stdlib.h>

#define INLINE_MATCH_FIELDS 8
#define INLINE_ACTIONS 8

typedef struct {
  const char *name;
  pi_p4info_match_type_t match_type;
  size_t bitwidth;
} _match_field_data_t;

typedef struct _table_data_s {
  const char *name;
  size_t num_match_fields;
  size_t num_actions;
  union {
    pi_p4_id_t direct[INLINE_MATCH_FIELDS];
    pi_p4_id_t *indirect;
  } match_field_ids;
  union {
    _match_field_data_t direct[INLINE_MATCH_FIELDS];
    _match_field_data_t *indirect;
  } match_field_data;
  union {
    pi_p4_id_t direct[INLINE_ACTIONS];
    pi_p4_id_t *indirect;
  } actions;
} _table_data_t;

void pi_p4info_table_init(pi_p4info_t *p4info, size_t num_tables) {
  p4info->num_tables = num_tables;
  p4info->tables = calloc(num_tables, sizeof(_table_data_t));
  p4info->table_name_map = (Pvoid_t) NULL;
}

void pi_p4info_table_free(pi_p4info_t *p4info) {
  free(p4info->tables);
}

void pi_p4info_table_add(pi_p4info_t *p4info, pi_p4_id_t table_id,
                         const char *name, size_t num_match_fields,
                         size_t num_actions) {
  (void) p4info; (void) table_id; (void) name; (void) num_match_fields;
  (void) num_actions;
}

void pi_p4info_table_add_match_field(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                     pi_p4_id_t field_id, const char *name,
                                     pi_p4info_match_type_t match_type,
                                     size_t bitwidth) {
  (void) p4info; (void) table_id; (void) field_id; (void) name;
  (void) match_type; (void) bitwidth;
}

void pi_p4info_table_add_action(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                pi_p4_id_t action_id) {
  (void) p4info; (void) table_id; (void) action_id;
}

pi_p4_id_t pi_p4info_table_id_from_name(const pi_p4info_t *p4info,
                                        const char *name) {
  (void) p4info; (void) name;
  return 0;
}

const char *pi_p4info_table_name_from_id(const pi_p4info_t *p4info,
                                         pi_p4_id_t table_id) {
  (void) p4info; (void) table_id;
  return NULL;
}

size_t pi_p4info_table_num_match_fields(const pi_p4info_t *p4info,
                                        pi_p4_id_t table_id) {
  (void) p4info; (void) table_id;
  return 0;
}

const pi_p4_id_t *pi_p4info_table_get_match_fields(const pi_p4info_t *p4info,
                                                   pi_p4_id_t table_id,
                                                   size_t *num_match_fields) {
  (void) p4info; (void) table_id; (void) num_match_fields;
  return NULL;
}

bool pi_p4info_table_is_match_field_of(const pi_p4info_t *p4info,
                                       pi_p4_id_t table_id,
                                       pi_p4_id_t field_id) {
  (void) p4info; (void) table_id; (void) field_id;
  return false;
}

size_t pi_p4info_table_num_actions(const pi_p4info_t *p4info,
                                   pi_p4_id_t table_id) {
  (void) p4info; (void) table_id;
  return 0;
}

bool pi_p4info_table_is_action_of(const pi_p4info_t *p4info,
                                  pi_p4_id_t table_id,
                                  pi_p4_id_t action_id) {
  (void) p4info; (void) table_id; (void) action_id;
  return false;
}

const pi_p4_id_t *pi_p4info_table_get_actions(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id,
                                              size_t *num_actions) {
  (void) p4info; (void) table_id; (void) num_actions;
  return NULL;
}
