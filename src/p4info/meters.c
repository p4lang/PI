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

#include "PI/p4info/meters.h"
#include "PI/int/pi_int.h"
#include "meters_int.h"
#include "p4info/p4info_struct.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct _meter_data_s {
  p4info_common_t common;
  char *name;
  pi_p4_id_t meter_id;
  pi_p4_id_t direct_table;  // PI_INVALID_ID if not direct
  // TODO(antonin): the API lets us configure this at runtime, do we really need
  // these?
  pi_p4info_meter_unit_t meter_unit;
  pi_p4info_meter_type_t meter_type;
  size_t size;
} _meter_data_t;

static _meter_data_t *get_meter(const pi_p4info_t *p4info,
                                pi_p4_id_t meter_id) {
  assert(PI_GET_TYPE_ID(meter_id) == PI_METER_ID);
  return p4info_get_at(p4info, meter_id);
}

static const char *retrieve_name(const void *data) {
  const _meter_data_t *meter = (const _meter_data_t *)data;
  return meter->name;
}

static void free_meter_data(void *data) {
  _meter_data_t *meter = (_meter_data_t *)data;
  if (!meter->name) return;
  free(meter->name);
  p4info_common_destroy(&meter->common);
}

void pi_p4info_meter_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *mArray = cJSON_CreateArray();
  const vector_t *meters = p4info->meters->vec;
  for (size_t i = 0; i < vector_size(meters); i++) {
    _meter_data_t *meter = vector_at(meters, i);
    cJSON *mObject = cJSON_CreateObject();

    cJSON_AddStringToObject(mObject, "name", meter->name);
    cJSON_AddNumberToObject(mObject, "id", meter->meter_id);
    cJSON_AddNumberToObject(mObject, "direct_table", meter->direct_table);
    cJSON_AddNumberToObject(mObject, "meter_unit", meter->meter_unit);
    cJSON_AddNumberToObject(mObject, "meter_type", meter->meter_type);
    cJSON_AddNumberToObject(mObject, "size", meter->size);

    p4info_common_serialize(mObject, &meter->common);

    cJSON_AddItemToArray(mArray, mObject);
  }
  cJSON_AddItemToObject(root, "meters", mArray);
}

void pi_p4info_meter_init(pi_p4info_t *p4info, size_t num_meters) {
  p4info_init_res(p4info, PI_METER_ID, num_meters, sizeof(_meter_data_t),
                  retrieve_name, free_meter_data, pi_p4info_meter_serialize);
}

void pi_p4info_meter_add(pi_p4info_t *p4info, pi_p4_id_t meter_id,
                         const char *name, pi_p4info_meter_unit_t meter_unit,
                         pi_p4info_meter_type_t meter_type, size_t size) {
  _meter_data_t *meter = p4info_add_res(p4info, meter_id, name);
  meter->name = strdup(name);
  meter->meter_id = meter_id;
  meter->meter_unit = meter_unit;
  meter->meter_type = meter_type;
  meter->direct_table = PI_INVALID_ID;
  meter->size = size;
}

void pi_p4info_meter_make_direct(pi_p4info_t *p4info, pi_p4_id_t meter_id,
                                 pi_p4_id_t direct_table_id) {
  _meter_data_t *meter = get_meter(p4info, meter_id);
  // TODO(antonin): cannot make direct twice, improve
  assert(meter->direct_table == PI_INVALID_ID);
  meter->direct_table = direct_table_id;
}

pi_p4_id_t pi_p4info_meter_id_from_name(const pi_p4info_t *p4info,
                                        const char *name) {
  return p4info_name_map_get(&p4info->meters->name_map, name);
}

const char *pi_p4info_meter_name_from_id(const pi_p4info_t *p4info,
                                         pi_p4_id_t meter_id) {
  _meter_data_t *meter = get_meter(p4info, meter_id);
  return meter->name;
}

pi_p4_id_t pi_p4info_meter_get_direct(const pi_p4info_t *p4info,
                                      pi_p4_id_t meter_id) {
  _meter_data_t *meter = get_meter(p4info, meter_id);
  return meter->direct_table;
}

pi_p4info_meter_unit_t pi_p4info_meter_get_unit(const pi_p4info_t *p4info,
                                                pi_p4_id_t meter_id) {
  _meter_data_t *meter = get_meter(p4info, meter_id);
  return meter->meter_unit;
}

pi_p4info_meter_type_t pi_p4info_meter_get_type(const pi_p4info_t *p4info,
                                                pi_p4_id_t meter_id) {
  _meter_data_t *meter = get_meter(p4info, meter_id);
  return meter->meter_type;
}

size_t pi_p4info_meter_get_size(const pi_p4info_t *p4info,
                                pi_p4_id_t meter_id) {
  _meter_data_t *meter = get_meter(p4info, meter_id);
  return meter->size;
}

pi_p4_id_t pi_p4info_meter_begin(const pi_p4info_t *p4info) {
  return pi_p4info_any_begin(p4info, PI_METER_ID);
}

pi_p4_id_t pi_p4info_meter_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return pi_p4info_any_next(p4info, id);
}

pi_p4_id_t pi_p4info_meter_end(const pi_p4info_t *p4info) {
  return pi_p4info_any_end(p4info, PI_METER_ID);
}
