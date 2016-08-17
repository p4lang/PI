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

#ifndef PI_SRC_P4INFO_P4INFO_STRUCT_H_
#define PI_SRC_P4INFO_P4INFO_STRUCT_H_

#include <PI/int/pi_int.h>

#include <stddef.h>

#include <Judy.h>

#include "p4info_vector.h"
#include "p4info_array.h"
#include "p4info_name_map.h"

typedef struct cJSON cJSON;

typedef void (*P4InfoSerializeFn)(cJSON *root, const pi_p4info_t *p4info);

typedef struct {
  int is_init;
  P4InfoFreeOneFn free_fn;
  P4InfoSerializeFn serialize_fn;
  p4info_array_t arr;
  p4info_name_map_t name_map;
} pi_p4info_res_t;

struct pi_p4info_s {
  pi_p4info_res_t resources[256];

  // for convenience, maybe remove later
  pi_p4info_res_t *actions;
  pi_p4info_res_t *tables;
  pi_p4info_res_t *fields;
  pi_p4info_res_t *act_profs;
  pi_p4info_res_t *counters;
  pi_p4info_res_t *meters;
};

static inline void *p4info_get_at(const pi_p4info_t *p4info, pi_p4_id_t id) {
  const pi_p4info_res_t *res = &p4info->resources[PI_GET_TYPE_ID(id)];
  size_t idx = id & 0xFFFF;
  return p4info_array_at(&res->arr, idx);
}

void p4info_init_res(pi_p4info_t *p4info, int res_type, size_t num,
                     size_t e_size, P4InfoFreeOneFn free_fn,
                     P4InfoSerializeFn serialize_fn);

#endif  // PI_SRC_P4INFO_P4INFO_STRUCT_H_
