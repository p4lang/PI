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

#include <PI/int/serialize.h>

#include <stdint.h>
#include <string.h>

size_t emit_uint32(char *dst, uint32_t v) {
  memcpy(dst, &v, sizeof(v));
  return sizeof(v);
}

size_t emit_uint64(char *dst, uint64_t v) {
  memcpy(dst, &v, sizeof(v));
  return sizeof(v);
}

size_t emit_p4_id(char *dst, pi_p4_id_t v) { return emit_uint32(dst, v); }

size_t emit_entry_handle(char *dst, pi_entry_handle_t v) {
  return emit_uint64(dst, v);
}

size_t emit_indirect_handle(char *dst, pi_indirect_handle_t v) {
  return emit_uint64(dst, v);
}

size_t emit_dev_id(char *dst, pi_dev_id_t v) {
  // TODO(antonin): change to uint16?
  return emit_uint32(dst, v);
}

size_t emit_dev_tgt(char *dst, pi_dev_tgt_t v) {
  size_t s = 0;
  s += emit_dev_id(dst, v.dev_id);
  s += emit_uint32(dst + s, v.dev_pipe_mask);
  return s;
}

size_t emit_status(char *dst, pi_status_t v) { return emit_uint32(dst, v); }

size_t emit_session_handle(char *dst, pi_session_handle_t v) {
  return emit_uint32(dst, v);
}

size_t emit_action_entry_type(char *dst, pi_action_entry_type_t v) {
  return emit_uint32(dst, v);
}

size_t emit_counter_value(char *dst, pi_counter_value_t v) {
  return emit_uint64(dst, v);
}

size_t emit_counter_data(char *dst, const pi_counter_data_t *v) {
  size_t s = 0;
  s += emit_uint32(dst, v->valid);
  s += emit_counter_value(dst + s, v->bytes);
  s += emit_counter_value(dst + s, v->packets);
  return s;
}

size_t emit_meter_spec(char *dst, const pi_meter_spec_t *v) {
  size_t s = 0;
  s += emit_uint64(dst, v->cir);
  s += emit_uint32(dst + s, v->cburst);
  s += emit_uint64(dst + s, v->pir);
  s += emit_uint32(dst + s, v->pburst);
  s += emit_uint32(dst + s, v->meter_unit);
  s += emit_uint32(dst + s, v->meter_type);
  return s;
}

size_t emit_learn_msg_id(char *dst, pi_learn_msg_id_t v) {
  return emit_uint64(dst, v);
}

size_t retrieve_uint32(const char *src, uint32_t *v) {
  memcpy(v, src, sizeof(*v));
  return sizeof(*v);
}

size_t retrieve_uint64(const char *src, uint64_t *v) {
  memcpy(v, src, sizeof(*v));
  return sizeof(*v);
}

size_t retrieve_p4_id(const char *src, pi_p4_id_t *v) {
  return retrieve_uint32(src, v);
}

size_t retrieve_entry_handle(const char *src, pi_entry_handle_t *v) {
  return retrieve_uint64(src, v);
}

size_t retrieve_indirect_handle(const char *src, pi_indirect_handle_t *v) {
  return retrieve_uint64(src, v);
}

size_t retrieve_dev_id(const char *src, pi_dev_id_t *v) {
  uint32_t tmp32;
  size_t s = retrieve_uint32(src, &tmp32);
  *v = tmp32;
  return s;
}

size_t retrieve_dev_tgt(const char *src, pi_dev_tgt_t *v) {
  size_t s = 0;
  s += retrieve_dev_id(src, &v->dev_id);
  uint32_t tmp32;
  s += retrieve_uint32(src + s, &tmp32);
  v->dev_pipe_mask = tmp32;
  return s;
}

size_t retrieve_status(const char *src, pi_status_t *v) {
  return retrieve_uint32(src, v);
}

size_t retrieve_session_handle(const char *src, pi_session_handle_t *v) {
  return retrieve_uint32(src, v);
}

size_t retrieve_action_entry_type(const char *src, pi_action_entry_type_t *v) {
  return retrieve_uint32(src, v);
}

size_t retrieve_counter_value(const char *src, pi_counter_value_t *v) {
  return retrieve_uint64(src, v);
}

size_t retrieve_counter_data(const char *src, pi_counter_data_t *v) {
  size_t s = 0;
  uint32_t tmp32;
  s += retrieve_uint32(src, &tmp32);
  v->valid = tmp32;
  s += retrieve_counter_value(src + s, &v->bytes);
  s += retrieve_counter_value(src + s, &v->packets);
  return s;
}

size_t retrieve_meter_spec(const char *src, pi_meter_spec_t *v) {
  size_t s = 0;
  s += retrieve_uint64(src, &v->cir);
  s += retrieve_uint32(src + s, &v->cburst);
  s += retrieve_uint64(src + s, &v->pir);
  s += retrieve_uint32(src + s, &v->pburst);
  uint32_t tmp32;
  s += retrieve_uint32(src + s, &tmp32);
  v->meter_unit = (pi_meter_unit_t)tmp32;
  s += retrieve_uint32(src + s, &tmp32);
  v->meter_type = (pi_meter_type_t)tmp32;
  return s;
}

size_t retrieve_learn_msg_id(const char *src, pi_learn_msg_id_t *v) {
  // works because pi_learn_msg_id_t is typedef'd from uint64
  return retrieve_uint64(src, v);
}
