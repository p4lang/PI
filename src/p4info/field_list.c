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

#include "PI/p4info/field_list.h"
#include "p4info/p4info_struct.h"
#include "PI/int/pi_int.h"
#include "field_list_int.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define INLINE_FIELDS 8

typedef struct _field_list_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t field_list_id;
  size_t num_fields;
  size_t fields_added;
  union {
    pi_p4_id_t direct[INLINE_FIELDS];
    pi_p4_id_t *indirect;
  } field_ids;
} _field_list_data_t;

static _field_list_data_t *get_field_list(const pi_p4info_t *p4info,
                                          pi_p4_id_t field_list_id) {
  assert(PI_GET_TYPE_ID(field_list_id) == PI_FIELD_LIST_ID);
  return p4info_get_at(p4info, field_list_id);
}

static pi_p4_id_t *get_field_ids(_field_list_data_t *field_list) {
  return (field_list->num_fields <= INLINE_FIELDS)
             ? field_list->field_ids.direct
             : field_list->field_ids.indirect;
}

static size_t num_field_lists(const pi_p4info_t *p4info) {
  return p4info->field_lists->arr.size;
}

static const char *retrieve_name(const void *data) {
  const _field_list_data_t *field_list = (const _field_list_data_t *)data;
  return field_list->name;
}

static void free_field_list_data(void *data) {
  _field_list_data_t *field_list = (_field_list_data_t *)data;
  if (!field_list->name) return;
  free(field_list->name);
  if (field_list->num_fields > INLINE_FIELDS) {
    assert(field_list->field_ids.indirect);
    free(field_list->field_ids.indirect);
  }
  p4info_common_destroy(&field_list->common);
}

void pi_p4info_field_list_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *lArray = cJSON_CreateArray();
  const p4info_array_t *field_lists = &p4info->field_lists->arr;
  for (size_t i = 0; i < field_lists->size; i++) {
    _field_list_data_t *field_list = p4info_array_at(field_lists, i);
    cJSON *lObject = cJSON_CreateObject();

    cJSON_AddStringToObject(lObject, "name", field_list->name);
    cJSON_AddNumberToObject(lObject, "id", field_list->field_list_id);

    cJSON *fieldsArray = cJSON_CreateArray();
    pi_p4_id_t *field_ids = get_field_ids(field_list);
    for (size_t j = 0; j < field_list->num_fields; j++) {
      cJSON *field = cJSON_CreateNumber(field_ids[j]);
      cJSON_AddItemToArray(fieldsArray, field);
    }
    cJSON_AddItemToObject(lObject, "fields", fieldsArray);

    p4info_common_serialize(lObject, &field_list->common);

    cJSON_AddItemToArray(lArray, lObject);
  }
  cJSON_AddItemToObject(root, "field_lists", lArray);
}

void pi_p4info_field_list_init(pi_p4info_t *p4info, size_t num_field_lists) {
  p4info_init_res(p4info, PI_FIELD_LIST_ID, num_field_lists,
                  sizeof(_field_list_data_t), retrieve_name,
                  free_field_list_data, pi_p4info_field_list_serialize);
}

void pi_p4info_field_list_add(pi_p4info_t *p4info, pi_p4_id_t field_list_id,
                              const char *name, size_t num_fields) {
  _field_list_data_t *field_list = get_field_list(p4info, field_list_id);
  field_list->name = strdup(name);
  field_list->field_list_id = field_list_id;
  field_list->num_fields = num_fields;
  if (num_fields > INLINE_FIELDS) {
    field_list->field_ids.indirect = calloc(num_fields, sizeof(pi_p4_id_t));
  }
  p4info_common_init(&field_list->common);

  p4info_name_map_add(&p4info->field_lists->name_map, field_list->name,
                      field_list_id);
}

void pi_p4info_field_list_add_field(pi_p4info_t *p4info,
                                    pi_p4_id_t field_list_id,
                                    pi_p4_id_t field_id) {
  _field_list_data_t *field_list = get_field_list(p4info, field_list_id);
  assert(field_list->fields_added < field_list->num_fields);
  get_field_ids(field_list)[field_list->fields_added] = field_id;
  field_list->fields_added++;
}

size_t pi_p4info_field_list_get_num(const pi_p4info_t *p4info) {
  return num_field_lists(p4info);
}

pi_p4_id_t pi_p4info_field_list_id_from_name(const pi_p4info_t *p4info,
                                             const char *name) {
  return p4info_name_map_get(&p4info->field_lists->name_map, name);
}

const char *pi_p4info_field_list_name_from_id(const pi_p4info_t *p4info,
                                              pi_p4_id_t field_list_id) {
  _field_list_data_t *field_list = get_field_list(p4info, field_list_id);
  return field_list->name;
}

size_t pi_p4info_field_list_num_fields(const pi_p4info_t *p4info,
                                       pi_p4_id_t field_list_id) {
  _field_list_data_t *field_list = get_field_list(p4info, field_list_id);
  return field_list->num_fields;
}

const pi_p4_id_t *pi_p4info_field_list_get_fields(const pi_p4info_t *p4info,
                                                  pi_p4_id_t field_list_id,
                                                  size_t *num_fields) {
  _field_list_data_t *field_list = get_field_list(p4info, field_list_id);
  *num_fields = field_list->num_fields;
  return get_field_ids(field_list);
}

#define PI_P4INFO_FL_ITERATOR_FIRST (PI_FIELD_LIST_ID << 24)
#define PI_P4INFO_FL_ITERATOR_END ((PI_FIELD_LIST_ID << 24) | 0xffffff)

pi_p4_id_t pi_p4info_field_list_begin(const pi_p4info_t *p4info) {
  return (num_field_lists(p4info) == 0) ? PI_P4INFO_FL_ITERATOR_END
                                        : PI_P4INFO_FL_ITERATOR_FIRST;
}

pi_p4_id_t pi_p4info_field_list_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return ((id & 0xffffff) == num_field_lists(p4info) - 1)
             ? PI_P4INFO_FL_ITERATOR_END
             : (id + 1);
}

pi_p4_id_t pi_p4info_field_list_end(const pi_p4info_t *p4info) {
  (void)p4info;
  return PI_P4INFO_FL_ITERATOR_END;
}
