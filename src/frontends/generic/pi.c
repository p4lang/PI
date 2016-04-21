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

#include "PI/frontends/generic/pi.h"
#include "PI/pi_p4info.h"
#include "pi_int.h"

#include <stdlib.h>
#include <string.h>

#define ALIGN 16

#define SAFEGUARD ((int) 0xabababab)

// possibility to unify more the match keys and action data code, but I don't
// know if they are going to diverge in the future

// MATCH KEYS

typedef struct {
  int safeguard;
  size_t data_offset_init;
  size_t data_offset_current;
  uint64_t fset;
  size_t size;
  pi_p4_id_t table_id;
  uint32_t nset;
} _fegen_mk_prefix_t;

#define MK_PREFIX_SPACE \
  ((sizeof(_fegen_mk_prefix_t) + (ALIGN - 1)) & (~(ALIGN - 1)))

pi_status_t pi_match_key_allocate(const pi_p4info_t *p4info,
                                  const pi_p4_id_t table_id,
                                  pi_match_key_t **key) {
  size_t s = 0;
  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, table_id);
  // 2 compact blobs per field to accomodate all match types
  s += 2 * num_match_fields * sizeof(_compact_v_t);
  size_t data_offset = s;
  for (size_t i = 0; i < num_match_fields; i++) {
    pi_p4info_match_field_info_t finfo;
    pi_p4info_table_match_field_info(p4info, table_id, i, &finfo);
    if (finfo.bitwidth > 64) {
      s += (finfo.bitwidth + 7) / 8;
    }
  }
  s += MK_PREFIX_SPACE;
  char *key_w_prefix = malloc(s);
  _fegen_mk_prefix_t *prefix = (_fegen_mk_prefix_t *) key_w_prefix;
  prefix->safeguard = SAFEGUARD;
  prefix->data_offset_init = data_offset;
  prefix->data_offset_current = data_offset;
  prefix->fset = 0;
  prefix->size = s - MK_PREFIX_SPACE;
  prefix->nset = 0;
  prefix->table_id = table_id;
  *key = (pi_match_key_t *) (key_w_prefix + MK_PREFIX_SPACE);

  return PI_STATUS_SUCCESS;
}

static _fegen_mk_prefix_t *get_mk_prefix(pi_match_key_t *key) {
  return (_fegen_mk_prefix_t *) (((char *) key) - MK_PREFIX_SPACE);
}

static void check_mk_prefix(const _fegen_mk_prefix_t *prefix) {
  assert(prefix->safeguard == SAFEGUARD);
}

pi_status_t pi_match_key_init(const pi_p4info_t *p4info, pi_match_key_t *key) {
  (void) p4info;
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  check_mk_prefix(prefix);
  prefix->data_offset_current = prefix->data_offset_init;
  prefix->fset = 0;
  prefix->nset = 0;
  return PI_STATUS_SUCCESS;
}

#define SIZEOF_DST_ARR sizeof(((_compact_v_t *) 0)->bytes)

static void dump_fv(pi_match_key_t *key, size_t index,
                    const pi_netv_t *fv) {
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  const char *src = fv->is_ptr ? fv->v.ptr : &fv->v.data[0];
  char *dst;
  if (fv->size <= SIZEOF_DST_ARR) {
    dst = key[index].bytes;
  } else {
    key[index].more_bytes = (char *) key + prefix->data_offset_current;
    prefix->data_offset_current += fv->size;
    dst = key[index].more_bytes;
  }
  memcpy(dst, src, fv->size);
}

static int mk_is_set(const _fegen_mk_prefix_t *prefix, size_t index) {
  return prefix->fset & ((uint64_t) 1 << index);
}

static void mk_update_fset(pi_match_key_t *key, size_t index) {
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  if(!mk_is_set(prefix, index)) {
    prefix->nset++;
    prefix->fset |= ((uint64_t) 1 << index);
  }
}

pi_status_t pi_match_key_exact_set(const pi_p4info_t *p4info,
                                   pi_match_key_t *key,
                                   const pi_netv_t *fv) {
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  size_t f_index = pi_p4info_table_match_field_index(p4info, prefix->table_id,
                                                     fv->obj_id);
  size_t index = f_index * 2;
  dump_fv(key, index, fv);
  mk_update_fset(key, index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_lpm_set(const pi_p4info_t *p4info,
                                 pi_match_key_t *key,
                                 const pi_netv_t *fv,
                                 const pi_prefix_length_t prefix_length) {
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  size_t f_index = pi_p4info_table_match_field_index(p4info, prefix->table_id,
                                                     fv->obj_id);
  size_t index = f_index * 2;
  dump_fv(key, index, fv);
  index += 1;
  key[index].v = prefix_length;
  mk_update_fset(key, index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_ternary_set(const pi_p4info_t *p4info,
                                     pi_match_key_t *key,
                                     const pi_netv_t *fv,
                                     const pi_netv_t *mask) {
  assert(fv->obj_id == mask->obj_id);
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  size_t f_index = pi_p4info_table_match_field_index(p4info, prefix->table_id,
                                                     fv->obj_id);
  size_t index = f_index * 2;
  dump_fv(key, index, fv);
  index += 1;
  dump_fv(key, index, mask);
  mk_update_fset(key, index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_range_set(const pi_p4info_t *p4info,
                                   pi_match_key_t *key,
                                   const pi_netv_t *start,
                                   const pi_netv_t *end) {
  assert(start->obj_id == end->obj_id);
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  size_t f_index = pi_p4info_table_match_field_index(p4info, prefix->table_id,
                                                     start->obj_id);
  size_t index = f_index * 2;
  dump_fv(key, index, start);
  index += 1;
  dump_fv(key, index, end);
  mk_update_fset(key, index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_destroy(pi_match_key_t *key) {
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  check_mk_prefix(prefix);
  free(prefix);
  return PI_STATUS_SUCCESS;
}


// ACTION DATA

typedef struct {
  int safeguard;
  size_t data_offset_init;
  size_t data_offset_current;
  uint64_t pset;
  size_t size;
  pi_p4_id_t action_id;
  uint32_t nset;
} _fegen_ad_prefix_t;

#define AD_PREFIX_SPACE \
  ((sizeof(_fegen_ad_prefix_t) + (ALIGN - 1)) & (~(ALIGN - 1)))

pi_status_t pi_action_data_allocate(const pi_p4info_t *p4info,
                                    const pi_p4_id_t action_id,
                                    pi_action_data_t **adata) {
  size_t s = 0;
  size_t num_params;
  const pi_p4_id_t *params = pi_p4info_action_get_params(p4info, action_id,
                                                         &num_params);
  s += num_params * sizeof(_compact_v_t);
  size_t data_offset = s;
  for (size_t i = 0; i < num_params; i++) {
    size_t bitwidth = pi_p4info_action_param_bitwidth(p4info, params[i]);
    if (bitwidth > 64) {
      s += (bitwidth + 7) / 8;
    }
  }
  s += AD_PREFIX_SPACE;
  char *adata_w_prefix = malloc(s);
  _fegen_ad_prefix_t *prefix = (_fegen_ad_prefix_t *) adata_w_prefix;
  prefix->safeguard = SAFEGUARD;
  prefix->data_offset_init = data_offset;
  prefix->data_offset_current = data_offset;
  prefix->pset = 0;
  prefix->size = s - AD_PREFIX_SPACE;
  prefix->nset = 0;
  prefix->action_id = action_id;
  *adata = (pi_action_data_t *) (adata_w_prefix + AD_PREFIX_SPACE);

  return PI_STATUS_SUCCESS;
}

static _fegen_ad_prefix_t *get_ad_prefix(pi_action_data_t *adata) {
  return (_fegen_ad_prefix_t *) (((char *) adata) - AD_PREFIX_SPACE);
}

static void check_ad_prefix(const _fegen_ad_prefix_t *prefix) {
  assert(prefix->safeguard == SAFEGUARD);
}

pi_status_t pi_action_data_init(const pi_p4info_t *p4info,
                                pi_action_data_t *adata) {
  (void) p4info;
  _fegen_ad_prefix_t *prefix = get_ad_prefix(adata);
  check_ad_prefix(prefix);
  prefix->data_offset_current = prefix->data_offset_init;
  prefix->pset = 0;
  prefix->nset = 0;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_action_data_arg_set(const pi_p4info_t *p4info,
                                   pi_action_data_t *adata,
                                   const pi_netv_t *argv) {
  (void) p4info;
  _fegen_ad_prefix_t *prefix = get_ad_prefix(adata);
  check_ad_prefix(prefix);

  pi_p4_id_t param_id = argv->obj_id;
  assert(pi_is_action_param_id(param_id));
  // TODO(antonin): check action
  size_t index = param_id & 0xff;

  const char *src = argv->is_ptr ? argv->v.ptr : &argv->v.data[0];
  char *dst;
  if (argv->size <= SIZEOF_DST_ARR) {
    dst = adata[index].bytes;
  } else {
    adata[index].more_bytes = (char *) adata + prefix->data_offset_current;
    prefix->data_offset_current += argv->size;
    dst = adata[index].more_bytes;
  }
  memcpy(dst, src, argv->size);

  int is_set =  prefix->pset & ((uint64_t) 1 << index);
  if(!is_set) {
    prefix->nset++;
    prefix->pset |= ((uint64_t) 1 << index);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t pi_action_data_destroy(pi_action_data_t *action_data) {
  _fegen_ad_prefix_t *prefix = get_ad_prefix(action_data);
  check_ad_prefix(prefix);
  free(prefix);
  return PI_STATUS_SUCCESS;
}
