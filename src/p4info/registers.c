/* Copyright 2026 Lorenzo Rinieri
 * SPDX-License-Identifier: Apache-2.0
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

#include "PI/p4info/registers.h"
#include "PI/int/pi_int.h"
#include "p4info/p4info_struct.h"
#include "registers_int.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct _register_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t register_id;
  size_t size;
  size_t bitwidth;  // 0 if the type of the cells is not a bitstring
} _register_data_t;

static _register_data_t *get_register(const pi_p4info_t *p4info,
                                      pi_p4_id_t register_id) {
  assert(PI_GET_TYPE_ID(register_id) == PI_REGISTER_ID);
  return p4info_get_at(p4info, register_id);
}

static const char *retrieve_name(const void *data) {
  const _register_data_t *reg = (const _register_data_t *)data;
  return reg->name;
}

static void free_register_data(void *data) {
  _register_data_t *reg = (_register_data_t *)data;
  if (!reg->name) return;
  free(reg->name);
  p4info_common_destroy(&reg->common);
}

static void pi_p4info_register_serialize(cJSON *root,
                                         const pi_p4info_t *p4info) {
  cJSON *rArray = cJSON_CreateArray();
  const vector_t *registers = p4info->registers->vec;
  for (size_t i = 0; i < vector_size(registers); i++) {
    _register_data_t *reg = vector_at(registers, i);
    cJSON *rObject = cJSON_CreateObject();

    cJSON_AddStringToObject(rObject, "name", reg->name);
    cJSON_AddNumberToObject(rObject, "id", reg->register_id);
    cJSON_AddNumberToObject(rObject, "size", reg->size);
    cJSON_AddNumberToObject(rObject, "bitwidth", reg->bitwidth);

    p4info_common_serialize(rObject, &reg->common);

    cJSON_AddItemToArray(rArray, rObject);
  }
  cJSON_AddItemToObject(root, "registers", rArray);
}

void pi_p4info_register_init(pi_p4info_t *p4info, size_t num_registers) {
  p4info_init_res(p4info, PI_REGISTER_ID, num_registers,
                  sizeof(_register_data_t), retrieve_name, free_register_data,
                  pi_p4info_register_serialize);
}

void pi_p4info_register_add(pi_p4info_t *p4info, pi_p4_id_t register_id,
                            const char *name, size_t size, size_t bitwidth) {
  char *name_copy = strdup(name);
  _register_data_t *reg = p4info_add_res(p4info, register_id, name_copy);
  reg->name = name_copy;
  reg->register_id = register_id;
  reg->size = size;
  reg->bitwidth = bitwidth;
}

pi_p4_id_t pi_p4info_register_id_from_name(const pi_p4info_t *p4info,
                                           const char *name) {
  return p4info_name_map_get(&p4info->registers->name_map, name);
}

const char *pi_p4info_register_name_from_id(const pi_p4info_t *p4info,
                                            pi_p4_id_t register_id) {
  _register_data_t *reg = get_register(p4info, register_id);
  return reg->name;
}

size_t pi_p4info_register_get_size(const pi_p4info_t *p4info,
                                   pi_p4_id_t register_id) {
  _register_data_t *reg = get_register(p4info, register_id);
  return reg->size;
}

size_t pi_p4info_register_get_bitwidth(const pi_p4info_t *p4info,
                                       pi_p4_id_t register_id) {
  _register_data_t *reg = get_register(p4info, register_id);
  return reg->bitwidth;
}

pi_p4_id_t pi_p4info_register_begin(const pi_p4info_t *p4info) {
  return pi_p4info_any_begin(p4info, PI_REGISTER_ID);
}

pi_p4_id_t pi_p4info_register_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return pi_p4info_any_next(p4info, id);
}

pi_p4_id_t pi_p4info_register_end(const pi_p4info_t *p4info) {
  return pi_p4info_any_end(p4info, PI_REGISTER_ID);
}
