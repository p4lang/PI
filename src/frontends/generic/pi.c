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

typedef struct {
  int safeguard;
  size_t data_offset_init;
  size_t data_offset_current;
  uint64_t fset;
  size_t size;
} _fe_prefix_t;

#define ALIGN 16
#define PREFIX_SPACE ((sizeof(_fe_prefix_t) + (ALIGN - 1)) & (~(ALIGN - 1)))

#define SAFEGUARD ((int) 0xabababab)

pi_status_t pi_match_key_allocate(const pi_p4info_t *p4info,
                                  const pi_p4_id_t table_id,
                                  pi_match_key_t **key) {
  size_t s = sizeof(pi_match_key_t);
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
  s += PREFIX_SPACE;
  char *key_w_prefix = malloc(s);
  _fe_prefix_t *prefix = (_fe_prefix_t *) key_w_prefix;
  prefix->safeguard = SAFEGUARD;
  prefix->data_offset_init = data_offset;
  prefix->data_offset_current = data_offset;
  prefix->fset = 0;
  prefix->size = s - PREFIX_SPACE;
  *key = (pi_match_key_t *) (key_w_prefix + PREFIX_SPACE);
  (*key)->nset = 0;
  (*key)->table_id = table_id;

  return PI_STATUS_SUCCESS;
}

static _fe_prefix_t *get_prefix(pi_match_key_t *key) {
  return (_fe_prefix_t *) (((char *) key) - PREFIX_SPACE);
}

static void check_prefix(const _fe_prefix_t *prefix) {
  assert(prefix->safeguard == SAFEGUARD);
}

pi_status_t pi_match_key_init(const pi_p4info_t *p4info, pi_match_key_t *key) {
  (void) p4info;
  _fe_prefix_t *prefix = get_prefix(key);
  check_prefix(prefix);
  prefix->data_offset_current = prefix->data_offset_init;
  prefix->fset = 0;
  key->nset = 0;
  return PI_STATUS_SUCCESS;
}

#define SIZEOF_DST_ARR sizeof(((_compact_v_t *) 0)->bytes)

static void dump_fv(pi_match_key_t *key, size_t index,
                    const pi_fvalue_t *fv) {
  _fe_prefix_t *prefix = get_prefix(key);
  const char *src = fv->is_ptr ? fv->v.ptr : &fv->v.data[0];
  char *dst;
  if (fv->size <= SIZEOF_DST_ARR) {
    dst = key->data[index].bytes;
  } else {
    key->data[index].more_bytes = (char *) key + prefix->data_offset_current;
    prefix->data_offset_current += fv->size;
    dst = key->data[index].more_bytes;
  }
  memcpy(dst, src, fv->size);
}

static int is_set(const _fe_prefix_t *prefix, size_t index) {
  return prefix->fset & ((uint64_t) 1 << index);
}

static void update_fset(pi_match_key_t *key, size_t index) {
  _fe_prefix_t *prefix = get_prefix(key);
  if(!is_set(prefix, index)) {
    key->nset++;
    prefix->fset |= ((uint64_t) 1 << index);
  }
}

pi_status_t pi_match_key_exact_set(const pi_p4info_t *p4info,
                                   pi_match_key_t *key,
                                   const pi_fvalue_t *fv) {
  size_t f_index = pi_p4info_table_match_field_index(p4info, key->table_id,
                                                     fv->fid);
  size_t index = f_index * 2;
  dump_fv(key, index, fv);
  update_fset(key, index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_lpm_set(const pi_p4info_t *p4info,
                                 pi_match_key_t *key,
                                 const pi_fvalue_t *fv,
                                 const pi_prefix_length_t prefix_length) {
  size_t f_index = pi_p4info_table_match_field_index(p4info, key->table_id,
                                                     fv->fid);
  size_t index = f_index * 2;
  dump_fv(key, index, fv);
  index += 1;
  key->data[index].v = prefix_length;
  update_fset(key, index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_ternary_set(const pi_p4info_t *p4info,
                                     pi_match_key_t *key,
                                     const pi_fvalue_t *fv,
                                     const pi_fvalue_t *mask) {
  assert(fv->fid == mask->fid);
  size_t f_index = pi_p4info_table_match_field_index(p4info, key->table_id,
                                                     fv->fid);
  size_t index = f_index * 2;
  dump_fv(key, index, fv);
  index += 1;
  dump_fv(key, index, mask);
  update_fset(key, index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_range_set(const pi_p4info_t *p4info,
                                   pi_match_key_t *key,
                                   const pi_fvalue_t *start,
                                   const pi_fvalue_t *end) {
  assert(start->fid == end->fid);
  size_t f_index = pi_p4info_table_match_field_index(p4info, key->table_id,
                                                     start->fid);
  size_t index = f_index * 2;
  dump_fv(key, index, start);
  index += 1;
  dump_fv(key, index, end);
  update_fset(key, index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_destroy(pi_match_key_t *key) {
  _fe_prefix_t *prefix = get_prefix(key);
  check_prefix(prefix);
  free(prefix);
  return PI_STATUS_SUCCESS;
}
