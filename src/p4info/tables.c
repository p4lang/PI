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
#include "tables_int.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define INLINE_MATCH_FIELDS 8
#define INLINE_ACTIONS 8
#define INLINE_DIRECT_RES 4

typedef struct {
  char *name;
  pi_p4_id_t field_id;
  pi_p4info_match_type_t match_type;
  size_t bitwidth;
  size_t offset;
} _match_field_data_t;

typedef struct _table_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t table_id;
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
  } action_ids;
  size_t match_fields_added;
  size_t actions_added;
  // PI_INVALID_ID if no const default action
  pi_p4_id_t const_default_action_id;
  // PI_INVALID_ID if default
  pi_p4_id_t implementation;
  size_t num_direct_resources;
  union {
    pi_p4_id_t direct[INLINE_DIRECT_RES];
    pi_p4_id_t *indirect;
  } direct_resources;
} _table_data_t;

static _table_data_t *get_table(const pi_p4info_t *p4info,
                                pi_p4_id_t table_id) {
  assert(PI_GET_TYPE_ID(table_id) == PI_TABLE_ID);
  return p4info_get_at(p4info, table_id);
}

static pi_p4_id_t *get_match_field_ids(_table_data_t *table) {
  return (table->num_match_fields <= INLINE_MATCH_FIELDS)
             ? table->match_field_ids.direct
             : table->match_field_ids.indirect;
}

static _match_field_data_t *get_match_field_data(_table_data_t *table) {
  return (table->num_match_fields <= INLINE_MATCH_FIELDS)
             ? table->match_field_data.direct
             : table->match_field_data.indirect;
}

static pi_p4_id_t *get_action_ids(_table_data_t *table) {
  return (table->num_actions <= INLINE_ACTIONS) ? table->action_ids.direct
                                                : table->action_ids.indirect;
}

static pi_p4_id_t *get_direct_resources(_table_data_t *table) {
  return (table->num_direct_resources <= INLINE_DIRECT_RES)
             ? table->direct_resources.direct
             : table->direct_resources.indirect;
}

static size_t num_tables(const pi_p4info_t *p4info) {
  return p4info->tables->arr.size;
}

static const char *retrieve_name(const void *data) {
  const _table_data_t *table = (const _table_data_t *)data;
  return table->name;
}

static void free_table_data(void *data) {
  _table_data_t *table = (_table_data_t *)data;
  if (!table->name) return;
  free(table->name);
  _match_field_data_t *match_fields = get_match_field_data(table);
  for (size_t j = 0; j < table->num_match_fields; j++) {
    _match_field_data_t *match_field = &match_fields[j];
    if (!match_field->name) continue;
    free(match_field->name);
  }
  if (table->num_match_fields > INLINE_MATCH_FIELDS) {
    assert(table->match_field_ids.indirect);
    assert(table->match_field_data.indirect);
    free(table->match_field_ids.indirect);
    free(table->match_field_data.indirect);
  }
  if (table->num_actions > INLINE_ACTIONS) {
    assert(table->action_ids.indirect);
    free(table->action_ids.indirect);
  }
  p4info_common_destroy(&table->common);
}

void pi_p4info_table_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *tArray = cJSON_CreateArray();
  const p4info_array_t *tables = &p4info->tables->arr;
  for (size_t i = 0; i < tables->size; i++) {
    _table_data_t *table = p4info_array_at(tables, i);
    cJSON *tObject = cJSON_CreateObject();

    cJSON_AddStringToObject(tObject, "name", table->name);
    cJSON_AddNumberToObject(tObject, "id", table->table_id);

    cJSON *mfArray = cJSON_CreateArray();
    _match_field_data_t *mf_data = get_match_field_data(table);
    for (size_t j = 0; j < table->num_match_fields; j++) {
      cJSON *mf = cJSON_CreateObject();
      cJSON_AddNumberToObject(mf, "id", mf_data[j].field_id);
      cJSON_AddNumberToObject(mf, "match_type", mf_data[j].match_type);
      cJSON_AddItemToArray(mfArray, mf);
    }
    cJSON_AddItemToObject(tObject, "match_fields", mfArray);

    cJSON *actionsArray = cJSON_CreateArray();
    pi_p4_id_t *action_ids = get_action_ids(table);
    for (size_t j = 0; j < table->num_actions; j++) {
      cJSON *action = cJSON_CreateNumber(action_ids[j]);
      cJSON_AddItemToArray(actionsArray, action);
    }
    cJSON_AddItemToObject(tObject, "actions", actionsArray);

    cJSON_AddNumberToObject(tObject, "const_default_action_id",
                            table->const_default_action_id);

    cJSON_AddNumberToObject(tObject, "implementation", table->implementation);

    cJSON *directresArray = cJSON_CreateArray();
    pi_p4_id_t *direct_res_ids = get_direct_resources(table);
    for (size_t j = 0; j < table->num_direct_resources; j++) {
      cJSON *direct_res = cJSON_CreateNumber(direct_res_ids[j]);
      cJSON_AddItemToArray(directresArray, direct_res);
    }
    cJSON_AddItemToObject(tObject, "direct_resources", directresArray);

    p4info_common_serialize(tObject, &table->common);

    cJSON_AddItemToArray(tArray, tObject);
  }
  cJSON_AddItemToObject(root, "tables", tArray);
}

void pi_p4info_table_init(pi_p4info_t *p4info, size_t num_tables) {
  p4info_init_res(p4info, PI_TABLE_ID, num_tables, sizeof(_table_data_t),
                  retrieve_name, free_table_data, pi_p4info_table_serialize);
}

void pi_p4info_table_add(pi_p4info_t *p4info, pi_p4_id_t table_id,
                         const char *name, size_t num_match_fields,
                         size_t num_actions) {
  _table_data_t *table = get_table(p4info, table_id);
  table->name = strdup(name);
  table->table_id = table_id;
  table->num_match_fields = num_match_fields;
  table->num_actions = num_actions;
  if (num_match_fields > INLINE_MATCH_FIELDS) {
    table->match_field_ids.indirect =
        calloc(num_match_fields, sizeof(pi_p4_id_t));
    table->match_field_data.indirect =
        calloc(num_match_fields, sizeof(_match_field_data_t));
  }
  if (num_actions > INLINE_ACTIONS) {
    table->action_ids.indirect = calloc(num_actions, sizeof(pi_p4_id_t));
  }

  table->const_default_action_id = PI_INVALID_ID;
  table->implementation = PI_INVALID_ID;
  table->num_direct_resources = 0;

  p4info_common_init(&table->common);

  p4info_name_map_add(&p4info->tables->name_map, table->name, table_id);
}

void pi_p4info_table_add_match_field(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                     pi_p4_id_t field_id, const char *name,
                                     pi_p4info_match_type_t match_type,
                                     size_t bitwidth) {
  _table_data_t *table = get_table(p4info, table_id);
  assert(table->match_fields_added < table->num_match_fields);
  _match_field_data_t *match_field =
      &get_match_field_data(table)[table->match_fields_added];
  assert(!match_field->name);
  match_field->name = strdup(name);
  match_field->field_id = field_id;
  match_field->match_type = match_type;
  match_field->bitwidth = bitwidth;
  get_match_field_ids(table)[table->match_fields_added] = field_id;

  if (table->match_fields_added == 0) {
    match_field->offset = 0;
  } else {
    _match_field_data_t *prev_field = match_field - 1;
    match_field->offset =
        prev_field->offset + get_match_key_size_one_field(
                                 prev_field->match_type, prev_field->bitwidth);
  }

  table->match_fields_added++;
}

void pi_p4info_table_add_action(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                pi_p4_id_t action_id) {
  _table_data_t *table = get_table(p4info, table_id);
  assert(table->actions_added < table->num_actions);
  get_action_ids(table)[table->actions_added] = action_id;
  table->actions_added++;
}

void pi_p4info_table_set_implementation(pi_p4info_t *p4info,
                                        pi_p4_id_t table_id,
                                        pi_p4_id_t implementation) {
  _table_data_t *table = get_table(p4info, table_id);
  table->implementation = implementation;
}

void pi_p4info_table_set_const_default_action(pi_p4info_t *p4info,
                                              pi_p4_id_t table_id,
                                              pi_p4_id_t default_action_id) {
  _table_data_t *table = get_table(p4info, table_id);
  assert(table->num_actions > 0);
  assert(pi_p4info_table_is_action_of(p4info, table_id, default_action_id));
  table->const_default_action_id = default_action_id;
}

void pi_p4info_table_add_direct_resource(pi_p4info_t *p4info,
                                         pi_p4_id_t table_id,
                                         pi_p4_id_t direct_res_id) {
  _table_data_t *table = get_table(p4info, table_id);
  get_direct_resources(table)[table->num_direct_resources] = direct_res_id;
  table->num_direct_resources++;
}

pi_p4_id_t pi_p4info_table_id_from_name(const pi_p4info_t *p4info,
                                        const char *name) {
  return p4info_name_map_get(&p4info->tables->name_map, name);
}

const char *pi_p4info_table_name_from_id(const pi_p4info_t *p4info,
                                         pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->name;
}

size_t pi_p4info_table_num_match_fields(const pi_p4info_t *p4info,
                                        pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->num_match_fields;
}

const pi_p4_id_t *pi_p4info_table_get_match_fields(const pi_p4info_t *p4info,
                                                   pi_p4_id_t table_id,
                                                   size_t *num_match_fields) {
  _table_data_t *table = get_table(p4info, table_id);
  *num_match_fields = table->num_match_fields;
  return get_match_field_ids(table);
}

bool pi_p4info_table_is_match_field_of(const pi_p4info_t *p4info,
                                       pi_p4_id_t table_id,
                                       pi_p4_id_t field_id) {
  _table_data_t *table = get_table(p4info, table_id);
  pi_p4_id_t *ids = get_match_field_ids(table);
  for (size_t i = 0; i < table->num_match_fields; i++)
    if (ids[i] == field_id) return true;
  return false;
}

size_t pi_p4info_table_match_field_index(const pi_p4info_t *p4info,
                                         pi_p4_id_t table_id,
                                         pi_p4_id_t field_id) {
  _table_data_t *table = get_table(p4info, table_id);
  pi_p4_id_t *ids = get_match_field_ids(table);
  for (size_t i = 0; i < table->num_match_fields; i++)
    if (ids[i] == field_id) return i;
  return (size_t)-1;
}

size_t pi_p4info_table_match_field_offset(const pi_p4info_t *p4info,
                                          pi_p4_id_t table_id,
                                          pi_p4_id_t field_id) {
  size_t index = pi_p4info_table_match_field_index(p4info, table_id, field_id);
  _table_data_t *table = get_table(p4info, table_id);
  _match_field_data_t *data = &get_match_field_data(table)[index];
  return data->offset;
}

void pi_p4info_table_match_field_info(const pi_p4info_t *p4info,
                                      pi_p4_id_t table_id, size_t index,
                                      pi_p4info_match_field_info_t *info) {
  _table_data_t *table = get_table(p4info, table_id);
  _match_field_data_t *data = &get_match_field_data(table)[index];
  info->name = data->name;
  info->field_id = data->field_id;
  info->match_type = data->match_type;
  info->bitwidth = data->bitwidth;
}

size_t pi_p4info_table_num_actions(const pi_p4info_t *p4info,
                                   pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->num_actions;
}

bool pi_p4info_table_is_action_of(const pi_p4info_t *p4info,
                                  pi_p4_id_t table_id, pi_p4_id_t action_id) {
  _table_data_t *table = get_table(p4info, table_id);
  pi_p4_id_t *ids = get_action_ids(table);
  for (size_t i = 0; i < table->num_actions; i++)
    if (ids[i] == action_id) return true;
  return false;
}

const pi_p4_id_t *pi_p4info_table_get_actions(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id,
                                              size_t *num_actions) {
  _table_data_t *table = get_table(p4info, table_id);
  *num_actions = table->num_actions;
  return get_action_ids(table);
}

bool pi_p4info_table_has_const_default_action(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return (table->const_default_action_id != PI_INVALID_ID);
}

pi_p4_id_t pi_p4info_table_get_const_default_action(const pi_p4info_t *p4info,
                                                    pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->const_default_action_id;
}

pi_p4_id_t pi_p4info_table_get_implementation(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id) {
  _table_data_t *table = get_table(p4info, table_id);
  return table->implementation;
}

bool pi_p4info_table_is_direct_resource_of(const pi_p4info_t *p4info,
                                           pi_p4_id_t table_id,
                                           pi_p4_id_t direct_res_id) {
  _table_data_t *table = get_table(p4info, table_id);
  pi_p4_id_t *ids = get_direct_resources(table);
  for (size_t i = 0; i < table->num_direct_resources; i++)
    if (ids[i] == direct_res_id) return true;
  return false;
}

const pi_p4_id_t *pi_p4info_table_get_direct_resources(
    const pi_p4info_t *p4info, pi_p4_id_t table_id,
    size_t *num_direct_resources) {
  _table_data_t *table = get_table(p4info, table_id);
  *num_direct_resources = table->num_direct_resources;
  return get_direct_resources(table);
}

#define PI_P4INFO_T_ITERATOR_FIRST (PI_TABLE_ID << 24)
#define PI_P4INFO_T_ITERATOR_END ((PI_TABLE_ID << 24) | 0xffffff)

pi_p4_id_t pi_p4info_table_begin(const pi_p4info_t *p4info) {
  return (num_tables(p4info) == 0) ? PI_P4INFO_T_ITERATOR_END
                                   : PI_P4INFO_T_ITERATOR_FIRST;
}

pi_p4_id_t pi_p4info_table_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return ((id & 0xffffff) == num_tables(p4info) - 1) ? PI_P4INFO_T_ITERATOR_END
                                                     : (id + 1);
}

pi_p4_id_t pi_p4info_table_end(const pi_p4info_t *p4info) {
  (void)p4info;
  return PI_P4INFO_T_ITERATOR_END;
}
