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

#include "PI/frontends/generic/pi.h"
#include "PI/p4info.h"
#include "PI/int/pi_int.h"
#include "PI/int/serialize.h"

#include <stdlib.h>
#include <string.h>

#define ALIGN 16

#define SAFEGUARD ((int)0xabababab)

// possibility to unify more the match keys and action data code, but I don't
// know if they are going to diverge in the future

// MATCH KEYS

typedef struct {
  int is_set;
  int offset;
} _fegen_mbr_info_t;

typedef struct {
  int safeguard;
  pi_p4_id_t table_id;
  uint32_t nset;
  size_t num_fields;
  _fegen_mbr_info_t f_info[1];
} _fegen_mk_prefix_t;

static size_t get_mk_prefix_space(size_t num_match_fields) {
  size_t s = sizeof(_fegen_mk_prefix_t);
  s += (num_match_fields - 1) * sizeof(_fegen_mbr_info_t);
  s = (s + (ALIGN - 1)) & (~(ALIGN - 1));
  // back pointer to beginning of prefix
  s += sizeof(_fegen_mk_prefix_t *);
  s = (s + (ALIGN - 1)) & (~(ALIGN - 1));
  return s;
}

pi_status_t pi_match_key_allocate(const pi_p4info_t *p4info,
                                  const pi_p4_id_t table_id,
                                  pi_match_key_t **key) {
  size_t s = 0;

  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, table_id);

  _fegen_mbr_info_t *offsets =
      malloc(sizeof(_fegen_mbr_info_t) * num_match_fields);

  for (size_t i = 0; i < num_match_fields; i++) {
    offsets[i].is_set = 0;
    offsets[i].offset = s;
    pi_p4info_match_field_info_t finfo;
    pi_p4info_table_match_field_info(p4info, table_id, i, &finfo);
    s += get_match_key_size_one_field(finfo.match_type, finfo.bitwidth);
  }
  size_t mk_size = s;

  size_t prefix_space = get_mk_prefix_space(num_match_fields);
  s += prefix_space;
  s += sizeof(pi_match_key_t);
  char *key_w_prefix = malloc(s);
  _fegen_mk_prefix_t *prefix = (_fegen_mk_prefix_t *)key_w_prefix;
  prefix->safeguard = SAFEGUARD;
  prefix->nset = 0;
  prefix->num_fields = num_match_fields;
  prefix->table_id = table_id;
  memcpy(prefix->f_info, offsets, sizeof(prefix->f_info[0]) * num_match_fields);
  free(offsets);

  *key = (pi_match_key_t *)(key_w_prefix + prefix_space);
  (*key)->p4info = p4info;
  (*key)->table_id = table_id;
  (*key)->data_size = mk_size;
  (*key)->data = (char *)(*key + 1);
  assert(sizeof(_fegen_mk_prefix_t *) <= ALIGN);
  char *back_ptr = ((char *)(*key)) - ALIGN;
  *(_fegen_mk_prefix_t **)back_ptr = prefix;

  return PI_STATUS_SUCCESS;
}

static _fegen_mk_prefix_t *get_mk_prefix(pi_match_key_t *key) {
  char *back_ptr = ((char *)key) - ALIGN;
  return *(_fegen_mk_prefix_t **)back_ptr;
}

static void check_mk_prefix(const _fegen_mk_prefix_t *prefix) {
  assert(prefix->safeguard == SAFEGUARD);
}

pi_status_t pi_match_key_init(pi_match_key_t *key) {
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  check_mk_prefix(prefix);
  prefix->nset = 0;
  for (size_t i = 0; i < prefix->num_fields; i++) prefix->f_info[i].is_set = 0;
  return PI_STATUS_SUCCESS;
}

static char *dump_fv(char *dst, const pi_netv_t *fv) {
  const char *src = fv->is_ptr ? fv->v.ptr : &fv->v.data[0];
  memcpy(dst, src, fv->size);
  return dst + fv->size;
}

static void mk_update_fset(_fegen_mk_prefix_t *prefix, size_t index) {
  if (!prefix->f_info[index].is_set) {
    prefix->nset++;
    prefix->f_info[index].is_set = 1;
  }
}

pi_status_t pi_match_key_exact_set(pi_match_key_t *key, const pi_netv_t *fv) {
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  size_t f_index = pi_p4info_table_match_field_index(
      key->p4info, prefix->table_id, fv->obj_id);
  _fegen_mbr_info_t *info = &prefix->f_info[f_index];
  char *dst = key->data + info->offset;
  dump_fv(dst, fv);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_exact_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                   pi_netv_t *fv) {
  size_t f_offset =
      pi_p4info_table_match_field_offset(key->p4info, key->table_id, fid);
  pi_getnetv_ptr(key->p4info, fid, key->data + f_offset, 0, fv);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_lpm_set(pi_match_key_t *key, const pi_netv_t *fv,
                                 const pi_prefix_length_t prefix_length) {
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  size_t f_index = pi_p4info_table_match_field_index(
      key->p4info, prefix->table_id, fv->obj_id);
  _fegen_mbr_info_t *info = &prefix->f_info[f_index];
  char *dst = key->data + info->offset;
  dst = dump_fv(dst, fv);
  emit_uint32(dst, prefix_length);
  mk_update_fset(prefix, f_index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_lpm_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                 pi_netv_t *fv,
                                 pi_prefix_length_t *prefix_length) {
  size_t f_offset =
      pi_p4info_table_match_field_offset(key->p4info, key->table_id, fid);
  const char *src = key->data + f_offset;
  pi_getnetv_ptr(key->p4info, fid, src, 0, fv);
  src += fv->size;
  uint32_t pLen;
  retrieve_uint32(src, &pLen);
  *prefix_length = (pi_prefix_length_t)pLen;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_ternary_set(pi_match_key_t *key, const pi_netv_t *fv,
                                     const pi_netv_t *mask) {
  assert(fv->obj_id == mask->obj_id);
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  size_t f_index = pi_p4info_table_match_field_index(
      key->p4info, prefix->table_id, fv->obj_id);
  _fegen_mbr_info_t *info = &prefix->f_info[f_index];
  char *dst = key->data + info->offset;
  dst = dump_fv(dst, fv);
  dump_fv(dst, mask);
  mk_update_fset(prefix, f_index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_ternary_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                     pi_netv_t *fv, pi_netv_t *mask) {
  size_t f_offset =
      pi_p4info_table_match_field_offset(key->p4info, key->table_id, fid);
  const char *src = key->data + f_offset;
  pi_getnetv_ptr(key->p4info, fid, src, 0, fv);
  src += fv->size;
  pi_getnetv_ptr(key->p4info, fid, src, 0, mask);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_range_set(pi_match_key_t *key, const pi_netv_t *start,
                                   const pi_netv_t *end) {
  assert(start->obj_id == end->obj_id);
  _fegen_mk_prefix_t *prefix = get_mk_prefix(key);
  size_t f_index = pi_p4info_table_match_field_index(
      key->p4info, prefix->table_id, start->obj_id);
  _fegen_mbr_info_t *info = &prefix->f_info[f_index];
  char *dst = key->data + info->offset;
  dst = dump_fv(dst, start);
  dump_fv(dst, end);
  mk_update_fset(prefix, f_index);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_match_key_range_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                   pi_netv_t *start, pi_netv_t *end) {
  size_t f_offset =
      pi_p4info_table_match_field_offset(key->p4info, key->table_id, fid);
  const char *src = key->data + f_offset;
  pi_getnetv_ptr(key->p4info, fid, src, 0, start);
  src += start->size;
  pi_getnetv_ptr(key->p4info, fid, src, 0, end);
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
  pi_p4_id_t action_id;
  uint32_t nset;
  size_t num_params;
  _fegen_mbr_info_t p_info[1];
} _fegen_ad_prefix_t;

static size_t get_ad_prefix_space(size_t num_params) {
  size_t s = sizeof(_fegen_ad_prefix_t);
  s += (num_params - 1) * sizeof(_fegen_mbr_info_t);
  s = (s + (ALIGN - 1)) & (~(ALIGN - 1));
  // back pointer to beginning of prefix
  s += sizeof(_fegen_ad_prefix_t *);
  s = (s + (ALIGN - 1)) & (~(ALIGN - 1));
  return s;
}

pi_status_t pi_action_data_allocate(const pi_p4info_t *p4info,
                                    const pi_p4_id_t action_id,
                                    pi_action_data_t **adata) {
  size_t s = 0;

  size_t num_params;
  const pi_p4_id_t *params =
      pi_p4info_action_get_params(p4info, action_id, &num_params);

  _fegen_mbr_info_t *offsets = malloc(sizeof(_fegen_mbr_info_t) * num_params);

  for (size_t i = 0; i < num_params; i++) {
    size_t bitwidth = pi_p4info_action_param_bitwidth(p4info, params[i]);
    offsets[i].is_set = 0;
    offsets[i].offset = s;
    s += (bitwidth + 7) / 8;
  }
  size_t ad_size = s;

  size_t prefix_space = get_ad_prefix_space(num_params);
  s += prefix_space;
  s += sizeof(pi_action_data_t);
  char *adata_w_prefix = malloc(s);
  _fegen_ad_prefix_t *prefix = (_fegen_ad_prefix_t *)adata_w_prefix;
  prefix->safeguard = SAFEGUARD;
  prefix->nset = 0;
  prefix->num_params = num_params;
  prefix->action_id = action_id;
  memcpy(prefix->p_info, offsets, sizeof(prefix->p_info[0]) * num_params);
  free(offsets);

  *adata = (pi_action_data_t *)(adata_w_prefix + prefix_space);
  (*adata)->p4info = p4info;
  (*adata)->action_id = action_id;
  (*adata)->data_size = ad_size;
  (*adata)->data = (char *)(*adata + 1);
  assert(sizeof(_fegen_ad_prefix_t *) <= ALIGN);
  char *back_ptr = ((char *)(*adata)) - ALIGN;
  *(_fegen_ad_prefix_t **)back_ptr = prefix;

  return PI_STATUS_SUCCESS;
}

static _fegen_ad_prefix_t *get_ad_prefix(pi_action_data_t *adata) {
  char *back_ptr = ((char *)adata) - ALIGN;
  return *(_fegen_ad_prefix_t **)back_ptr;
}

static void check_ad_prefix(const _fegen_ad_prefix_t *prefix) {
  assert(prefix->safeguard == SAFEGUARD);
}

pi_status_t pi_action_data_init(pi_action_data_t *adata) {
  _fegen_ad_prefix_t *prefix = get_ad_prefix(adata);
  check_ad_prefix(prefix);
  prefix->nset = 0;
  for (size_t i = 0; i < prefix->num_params; i++) prefix->p_info[i].is_set = 0;
  return PI_STATUS_SUCCESS;
}

pi_p4_id_t pi_action_data_action_id_get(const pi_action_data_t *adata) {
  return adata->action_id;
}

pi_status_t pi_action_data_arg_set(pi_action_data_t *adata,
                                   const pi_netv_t *argv) {
  _fegen_ad_prefix_t *prefix = get_ad_prefix(adata);
  check_ad_prefix(prefix);

  pi_p4_id_t param_id = argv->obj_id;
  assert(pi_is_action_param_id(param_id));
  // TODO(antonin): check action
  size_t index = param_id & 0xff;

  const char *src = argv->is_ptr ? argv->v.ptr : &argv->v.data[0];
  char *dst = adata->data + prefix->p_info[index].offset;
  memcpy(dst, src, argv->size);

  if (!prefix->p_info[index].is_set) {
    prefix->nset++;
    prefix->p_info[index].is_set = 1;
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t pi_action_data_arg_get(const pi_action_data_t *adata,
                                   pi_p4_id_t pid, pi_netv_t *argv) {
  size_t offset = pi_p4info_action_param_offset(adata->p4info, pid);
  const char *src = adata->data + offset;
  pi_getnetv_ptr(adata->p4info, pid, src, 0, argv);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_action_data_destroy(pi_action_data_t *action_data) {
  _fegen_ad_prefix_t *prefix = get_ad_prefix(action_data);
  check_ad_prefix(prefix);
  free(prefix);
  return PI_STATUS_SUCCESS;
}
