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

#include "PI/p4info/fields.h"
#include "p4info/p4info_struct.h"
#include "PI/int/pi_int.h"
#include "fields_int.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct _field_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t field_id;
  size_t bitwidth;
  char byte0_mask;
} _field_data_t;

static _field_data_t *get_field(const pi_p4info_t *p4info,
                                pi_p4_id_t field_id) {
  assert(PI_GET_TYPE_ID(field_id) == PI_FIELD_ID);
  return p4info_get_at(p4info, field_id);
}

static size_t num_fields(const pi_p4info_t *p4info) {
  return p4info->fields->arr.size;
}

static const char *retrieve_name(const void *data) {
  const _field_data_t *field = (const _field_data_t *)data;
  return field->name;
}

static void free_field_data(void *data) {
  _field_data_t *field = (_field_data_t *)data;
  if (!field->name) return;
  free(field->name);
  p4info_common_destroy(&field->common);
}

void pi_p4info_field_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *fArray = cJSON_CreateArray();
  const p4info_array_t *fields = &p4info->fields->arr;
  for (size_t i = 0; i < fields->size; i++) {
    _field_data_t *field = p4info_array_at(fields, i);
    cJSON *fObject = cJSON_CreateObject();

    cJSON_AddStringToObject(fObject, "name", field->name);
    cJSON_AddNumberToObject(fObject, "id", field->field_id);
    cJSON_AddNumberToObject(fObject, "bitwidth", field->bitwidth);

    p4info_common_serialize(fObject, &field->common);

    cJSON_AddItemToArray(fArray, fObject);
  }
  cJSON_AddItemToObject(root, "fields", fArray);
}

void pi_p4info_field_init(pi_p4info_t *p4info, size_t num_fields) {
  p4info_init_res(p4info, PI_FIELD_ID, num_fields, sizeof(_field_data_t),
                  retrieve_name, free_field_data, pi_p4info_field_serialize);
}

static char get_byte0_mask(size_t bitwidth) {
  if (bitwidth % 8 == 0) return 0xff;
  int nbits = bitwidth % 8;
  return ((1 << nbits) - 1);
}

void pi_p4info_field_add(pi_p4info_t *p4info, pi_p4_id_t field_id,
                         const char *name, size_t bitwidth) {
  _field_data_t *field = get_field(p4info, field_id);
  field->name = strdup(name);
  field->field_id = field_id;
  field->bitwidth = bitwidth;
  field->byte0_mask = get_byte0_mask(bitwidth);
  p4info_common_init(&field->common);

  p4info_name_map_add(&p4info->fields->name_map, field->name, field_id);
}

pi_p4_id_t pi_p4info_field_id_from_name(const pi_p4info_t *p4info,
                                        const char *name) {
  return p4info_name_map_get(&p4info->fields->name_map, name);
}

const char *pi_p4info_field_name_from_id(const pi_p4info_t *p4info,
                                         pi_p4_id_t field_id) {
  _field_data_t *field = get_field(p4info, field_id);
  return field->name;
}

size_t pi_p4info_field_bitwidth(const pi_p4info_t *p4info,
                                pi_p4_id_t field_id) {
  _field_data_t *field = get_field(p4info, field_id);
  return field->bitwidth;
}

char pi_p4info_field_byte0_mask(const pi_p4info_t *p4info,
                                pi_p4_id_t field_id) {
  _field_data_t *field = get_field(p4info, field_id);
  return field->byte0_mask;
}

#define PI_P4INFO_F_ITERATOR_FIRST (PI_FIELD_ID << 24)
#define PI_P4INFO_F_ITERATOR_END ((PI_FIELD_ID << 24) | 0xffffff)

pi_p4_id_t pi_p4info_field_begin(const pi_p4info_t *p4info) {
  return (num_fields(p4info) == 0) ? PI_P4INFO_F_ITERATOR_END
                                   : PI_P4INFO_F_ITERATOR_FIRST;
}

pi_p4_id_t pi_p4info_field_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return ((id & 0xffffff) == num_fields(p4info) - 1) ? PI_P4INFO_F_ITERATOR_END
                                                     : (id + 1);
}

pi_p4_id_t pi_p4info_field_end(const pi_p4info_t *p4info) {
  (void)p4info;
  return PI_P4INFO_F_ITERATOR_END;
}
