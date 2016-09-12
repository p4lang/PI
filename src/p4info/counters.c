/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "PI/p4info/counters.h"
#include "p4info/p4info_struct.h"
#include "PI/int/pi_int.h"
#include "counters_int.h"

#include <cJSON/cJSON.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct _counter_data_s {
  char *name;
  pi_p4_id_t counter_id;
  pi_p4_id_t direct_table;                // PI_INVALID_ID if not direct
  pi_p4info_counter_unit_t counter_unit;  // mostly ignored
  size_t size;
} _counter_data_t;

static _counter_data_t *get_counter(const pi_p4info_t *p4info,
                                    pi_p4_id_t counter_id) {
  assert(PI_GET_TYPE_ID(counter_id) == PI_COUNTER_ID);
  return p4info_get_at(p4info, counter_id);
}

static size_t num_counters(const pi_p4info_t *p4info) {
  return p4info->counters->arr.size;
}

static const char *retrieve_name(const void *data) {
  const _counter_data_t *counter = (const _counter_data_t *)data;
  return counter->name;
}

static void free_counter_data(void *data) {
  _counter_data_t *counter = (_counter_data_t *)data;
  if (!counter->name) return;
  free(counter->name);
}

void pi_p4info_counter_serialize(cJSON *root, const pi_p4info_t *p4info) {
  cJSON *cArray = cJSON_CreateArray();
  const p4info_array_t *counters = &p4info->counters->arr;
  for (size_t i = 0; i < counters->size; i++) {
    _counter_data_t *counter = p4info_array_at(counters, i);
    cJSON *cObject = cJSON_CreateObject();

    cJSON_AddStringToObject(cObject, "name", counter->name);
    cJSON_AddNumberToObject(cObject, "id", counter->counter_id);
    cJSON_AddNumberToObject(cObject, "direct_table", counter->direct_table);
    cJSON_AddNumberToObject(cObject, "counter_unit", counter->counter_unit);
    cJSON_AddNumberToObject(cObject, "size", counter->size);

    cJSON_AddItemToArray(cArray, cObject);
  }
  cJSON_AddItemToObject(root, "counters", cArray);
}

void pi_p4info_counter_init(pi_p4info_t *p4info, size_t num_counters) {
  p4info_init_res(p4info, PI_COUNTER_ID, num_counters, sizeof(_counter_data_t),
                  retrieve_name, free_counter_data,
                  pi_p4info_counter_serialize);
}

void pi_p4info_counter_add(pi_p4info_t *p4info, pi_p4_id_t counter_id,
                           const char *name,
                           pi_p4info_counter_unit_t counter_unit, size_t size) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  counter->name = strdup(name);
  counter->counter_id = counter_id;
  counter->counter_unit = counter_unit;
  counter->direct_table = PI_INVALID_ID;
  counter->size = size;

  p4info_name_map_add(&p4info->counters->name_map, counter->name, counter_id);
}

void pi_p4info_counter_make_direct(pi_p4info_t *p4info, pi_p4_id_t counter_id,
                                   pi_p4_id_t direct_table_id) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  // TODO(antonin): cannot make direct twice, improve
  assert(counter->direct_table == PI_INVALID_ID);
  counter->direct_table = direct_table_id;
}

pi_p4_id_t pi_p4info_counter_id_from_name(const pi_p4info_t *p4info,
                                          const char *name) {
  return p4info_name_map_get(&p4info->counters->name_map, name);
}

const char *pi_p4info_counter_name_from_id(const pi_p4info_t *p4info,
                                           pi_p4_id_t counter_id) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  return counter->name;
}

pi_p4_id_t pi_p4info_counter_get_direct(const pi_p4info_t *p4info,
                                        pi_p4_id_t counter_id) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  return counter->direct_table;
}

pi_p4info_counter_unit_t pi_p4info_counter_get_unit(const pi_p4info_t *p4info,
                                                    pi_p4_id_t counter_id) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  return counter->counter_unit;
}

size_t pi_p4info_counter_get_size(const pi_p4info_t *p4info,
                                  pi_p4_id_t counter_id) {
  _counter_data_t *counter = get_counter(p4info, counter_id);
  return counter->size;
}

#define PI_P4INFO_C_ITERATOR_FIRST (PI_COUNTER_ID << 24)
#define PI_P4INFO_C_ITERATOR_END ((PI_COUNTER_ID << 24) | 0xffffff)

pi_p4_id_t pi_p4info_counter_begin(const pi_p4info_t *p4info) {
  return (num_counters(p4info) == 0) ? PI_P4INFO_C_ITERATOR_END
                                     : PI_P4INFO_C_ITERATOR_FIRST;
}

pi_p4_id_t pi_p4info_counter_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return ((id & 0xffffff) == num_counters(p4info) - 1)
             ? PI_P4INFO_C_ITERATOR_END
             : (id + 1);
}

pi_p4_id_t pi_p4info_counter_end(const pi_p4info_t *p4info) {
  (void)p4info;
  return PI_P4INFO_C_ITERATOR_END;
}
