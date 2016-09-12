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

#ifndef PI_SRC_P4INFO_P4INFO_STRUCT_H_
#define PI_SRC_P4INFO_P4INFO_STRUCT_H_

#include <PI/int/pi_int.h>

#include <stddef.h>

#include <Judy.h>

#include "p4info_array.h"
#include "p4info_name_map.h"

typedef struct cJSON cJSON;

typedef void (*P4InfoSerializeFn)(cJSON *root, const pi_p4info_t *p4info);

// best that we can do?
typedef const char *(*P4InfoRetrieveNameFn)(const void *);

typedef struct {
  int is_init;
  P4InfoRetrieveNameFn retrieve_name_fn;
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
  pi_p4info_res_t *field_lists;
  pi_p4info_res_t *act_profs;
  pi_p4info_res_t *counters;
  pi_p4info_res_t *meters;
};

static inline size_t num_res(const pi_p4info_t *p4info,
                             pi_res_type_id_t res_type) {
  const pi_p4info_res_t *res = &p4info->resources[res_type];
  if (!res->is_init) return 0;
  return res->arr.size;
}

static inline void *p4info_get_at(const pi_p4info_t *p4info, pi_p4_id_t id) {
  const pi_p4info_res_t *res = &p4info->resources[PI_GET_TYPE_ID(id)];
  size_t idx = id & 0xFFFF;
  return p4info_array_at(&res->arr, idx);
}

void p4info_init_res(pi_p4info_t *p4info, pi_res_type_id_t res_type, size_t num,
                     size_t e_size, P4InfoRetrieveNameFn retrieve_name_fn,
                     P4InfoFreeOneFn free_fn, P4InfoSerializeFn serialize_fn);

#endif  // PI_SRC_P4INFO_P4INFO_STRUCT_H_
