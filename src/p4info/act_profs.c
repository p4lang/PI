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
#include "act_profs_int.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TABLES 8

typedef struct _act_prof_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t act_prof_id;
  size_t num_tables;
  // TODO(antonin): remove restriction on amount of table references?
  pi_p4_id_t table_ids[MAX_TABLES];
  bool with_selector;
} _act_prof_data_t;

static _act_prof_data_t *get_act_prof(const pi_p4info_t *p4info,
                                      pi_p4_id_t act_prof_id) {
  assert(PI_GET_TYPE_ID(act_prof_id) == PI_ACT_PROF_ID);
  return p4info_get_at(p4info, act_prof_id);
}

static size_t num_act_profs(const pi_p4info_t *p4info) {
  return p4info->act_profs->arr.size;
}

static const char *retrieve_name(const void *data) {
  const _act_prof_data_t *act_prof = (const _act_prof_data_t *)data;
  return act_prof->name;
}

static void free_act_prof_data(void *data) {
  _act_prof_data_t *act_prof = (_act_prof_data_t *)data;
  if (!act_prof->name) return;
  free(act_prof->name);
  p4info_common_destroy(&act_prof->common);
}

void pi_p4info_act_prof_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *aArray = cJSON_CreateArray();
  const p4info_array_t *act_profs = &p4info->act_profs->arr;
  for (size_t i = 0; i < act_profs->size; i++) {
    _act_prof_data_t *act_prof = p4info_array_at(act_profs, i);
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

    p4info_common_serialize(aObject, &act_prof->common);

    cJSON_AddItemToArray(aArray, aObject);
  }
  cJSON_AddItemToObject(root, "act_profs", aArray);
}

void pi_p4info_act_prof_init(pi_p4info_t *p4info, size_t num_act_profs) {
  p4info_init_res(p4info, PI_ACT_PROF_ID, num_act_profs,
                  sizeof(_act_prof_data_t), retrieve_name, free_act_prof_data,
                  pi_p4info_act_prof_serialize);
}

void pi_p4info_act_prof_add(pi_p4info_t *p4info, pi_p4_id_t act_prof_id,
                            const char *name, bool with_selector) {
  _act_prof_data_t *act_prof = get_act_prof(p4info, act_prof_id);
  act_prof->name = strdup(name);
  act_prof->act_prof_id = act_prof_id;
  act_prof->num_tables = 0;
  act_prof->with_selector = with_selector;
  p4info_common_init(&act_prof->common);

  p4info_name_map_add(&p4info->act_profs->name_map, act_prof->name,
                      act_prof_id);
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
  return p4info_name_map_get(&p4info->act_profs->name_map, name);
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
  return (num_act_profs(p4info) == 0) ? PI_P4INFO_A_ITERATOR_END
                                      : PI_P4INFO_A_ITERATOR_FIRST;
}

pi_p4_id_t pi_p4info_act_prof_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return ((id & 0xffffff) == num_act_profs(p4info) - 1)
             ? PI_P4INFO_A_ITERATOR_END
             : (id + 1);
}

pi_p4_id_t pi_p4info_act_prof_end(const pi_p4info_t *p4info) {
  (void)p4info;
  return PI_P4INFO_A_ITERATOR_END;
}
