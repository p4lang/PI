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

#include "PI/p4info/tables.h"
#include "p4info/p4info_struct.h"
#include "PI/int/pi_int.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TABLES 8

typedef struct _act_prof_data_s {
  char *name;
  pi_p4_id_t act_prof_id;
  size_t num_tables;
  // TODO(antonin): remove restriction on amount of table references?
  pi_p4_id_t table_ids[MAX_TABLES];
  bool with_selector;
} _act_prof_data_t;

static size_t get_act_prof_idx(pi_p4_id_t act_prof_id) {
  assert(PI_GET_TYPE_ID(act_prof_id) == PI_ACT_PROF_ID);
  return act_prof_id & 0xFFFF;
}

static _act_prof_data_t *get_act_prof(const pi_p4info_t *p4info,
                                      pi_p4_id_t act_prof_id) {
  size_t act_prof_idx = get_act_prof_idx(act_prof_id);
  assert(act_prof_idx < p4info->num_act_profs);
  return &p4info->act_profs[act_prof_idx];
}

void pi_p4info_act_prof_init(pi_p4info_t *p4info, size_t num_act_profs) {
  p4info->num_act_profs = num_act_profs;
  p4info->act_profs = calloc(num_act_profs, sizeof(_act_prof_data_t));
  p4info->act_prof_name_map = (Pvoid_t)NULL;
}

void pi_p4info_act_prof_free(pi_p4info_t *p4info) {
  for (size_t i = 0; i < p4info->num_act_profs; i++) {
    _act_prof_data_t *act_prof = &p4info->act_profs[i];
    if (!act_prof->name) continue;
    free(act_prof->name);
  }
  free(p4info->act_profs);
  Word_t Rc_word;
  JSLFA(Rc_word, p4info->act_prof_name_map);
}

void pi_p4info_act_prof_add(pi_p4info_t *p4info, pi_p4_id_t act_prof_id,
                            const char *name, bool with_selector) {
  _act_prof_data_t *act_prof = get_act_prof(p4info, act_prof_id);
  act_prof->name = strdup(name);
  act_prof->act_prof_id = act_prof_id;
  act_prof->num_tables = 0;
  act_prof->with_selector = with_selector;

  Word_t *act_prof_id_ptr;
  JSLI(act_prof_id_ptr, p4info->act_prof_name_map,
       (const uint8_t *)act_prof->name);
  *act_prof_id_ptr = act_prof_id;
}

void pi_p4info_act_prof_add_table(pi_p4info_t *p4info, pi_p4_id_t act_prof_id,
                                  pi_p4_id_t table_id) {
  _act_prof_data_t *act_prof = get_act_prof(p4info, act_prof_id);
  assert(act_prof->num_tables < MAX_TABLES);
  act_prof->table_ids[act_prof->num_tables] = table_id;
  act_prof->num_tables++;
}

pi_p4_id_t pi_p4info_act_prof_id_from_name(const pi_p4info_t *p4info,
                                           const char *name) {
  Word_t *act_prof_id_ptr;
  JSLG(act_prof_id_ptr, p4info->act_prof_name_map, (const uint8_t *)name);
  if (!act_prof_id_ptr) return PI_INVALID_ID;
  return *act_prof_id_ptr;
}

const char *pi_p4info_act_prof_name_from_id(const pi_p4info_t *p4info,
                                            pi_p4_id_t act_prof_id) {
  _act_prof_data_t *act_prof = get_act_prof(p4info, act_prof_id);
  return act_prof->name;
}

bool pi_p4info_act_prof_has_selector(const pi_p4info_t *p4info,
                                     pi_p4_id_t act_prof_id) {
  _act_prof_data_t *act_prof = get_act_prof(p4info, act_prof_id);
  return act_prof->with_selector;
}

const pi_p4_id_t *pi_p4info_act_prof_get_tables(const pi_p4info_t *p4info,
                                                pi_p4_id_t act_prof_id,
                                                size_t *num_tables) {
  _act_prof_data_t *act_prof = get_act_prof(p4info, act_prof_id);
  *num_tables = act_prof->num_tables;
  return act_prof->table_ids;
}

const pi_p4_id_t *pi_p4info_act_prof_get_actions(const pi_p4info_t *p4info,
                                                 pi_p4_id_t act_prof_id,
                                                 size_t *num_actions) {
  *num_actions = 0;
  _act_prof_data_t *act_prof = get_act_prof(p4info, act_prof_id);
  // actions are stored in tables, if no tables has been referenced for this
  // action profile, then we cannot list the actions
  if (act_prof->num_tables == 0) return NULL;
  pi_p4_id_t one_t_id = act_prof->table_ids[0];
  return pi_p4info_table_get_actions(p4info, one_t_id, num_actions);
}

#define PI_P4INFO_A_ITERATOR_FIRST (PI_ACT_PROF_ID << 24)
#define PI_P4INFO_A_ITERATOR_END ((PI_ACT_PROF_ID << 24) | 0xffffff)

pi_p4_id_t pi_p4info_act_prof_begin(const pi_p4info_t *p4info) {
  return (p4info->num_act_profs == 0) ? PI_P4INFO_A_ITERATOR_END
                                      : PI_P4INFO_A_ITERATOR_FIRST;
}

pi_p4_id_t pi_p4info_act_prof_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return ((id & 0xffffff) == p4info->num_act_profs - 1)
             ? PI_P4INFO_A_ITERATOR_END
             : (id + 1);
}

pi_p4_id_t pi_p4info_act_prof_end(const pi_p4info_t *p4info) {
  (void)p4info;
  return PI_P4INFO_A_ITERATOR_END;
}

void pi_p4info_act_prof_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *aArray = cJSON_CreateArray();
  for (size_t i = 0; i < p4info->num_act_profs; i++) {
    _act_prof_data_t *act_prof = &p4info->act_profs[i];
    cJSON *aObject = cJSON_CreateObject();

    cJSON_AddStringToObject(aObject, "name", act_prof->name);
    cJSON_AddNumberToObject(aObject, "id", act_prof->act_prof_id);

    cJSON *tablesArray = cJSON_CreateArray();
    for (size_t j = 0; j < act_prof->num_tables; j++) {
      cJSON *table = cJSON_CreateNumber(act_prof->table_ids[j]);
      cJSON_AddItemToArray(tablesArray, table);
    }
    cJSON_AddItemToObject(aObject, "tables", tablesArray);

    cJSON_AddBoolToObject(aObject, "with_selector", act_prof->with_selector);

    cJSON_AddItemToArray(aArray, aObject);
  }
  cJSON_AddItemToObject(root, "act_profs", aArray);
}
