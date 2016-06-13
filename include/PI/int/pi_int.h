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

#ifndef PI_INT_PI_INT_H_
#define PI_INT_PI_INT_H_

#include "PI/pi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PI_ACTION_ID        0x01
#define PI_TABLE_ID         0x02
#define PI_ACTION_PARAM_ID  0x03
#define PI_FIELD_ID         0x04

static inline pi_p4_id_t pi_make_action_id(uint16_t index) {
  return (PI_ACTION_ID << 24) | index;
}

static inline pi_p4_id_t pi_make_table_id(uint16_t index) {
  return (PI_TABLE_ID << 24) | index;
}

static inline pi_p4_id_t pi_make_action_param_id(pi_p4_id_t action_id,
                                                 uint8_t index) {
  uint16_t action_index = action_id & 0xffff;
  return (PI_ACTION_PARAM_ID << 24) | (action_index << 8) | index;
}

static inline pi_p4_id_t pi_make_field_id(uint16_t index) {
  return (PI_FIELD_ID << 24) | index;
}

#define PI_GET_TYPE_ID(id) (id >> 24)

// TODO(antonin): find a better location
static inline size_t get_match_key_size_one_field(
    pi_p4info_match_type_t match_type, size_t bitwidth) {
  size_t nbytes = (bitwidth + 7) / 8;
  switch (match_type) {
    case PI_P4INFO_MATCH_TYPE_VALID:
      assert(nbytes == 1);
    case PI_P4INFO_MATCH_TYPE_EXACT:
      return nbytes;
    case PI_P4INFO_MATCH_TYPE_LPM:
      return nbytes + sizeof(uint32_t);
    case PI_P4INFO_MATCH_TYPE_TERNARY:
    case PI_P4INFO_MATCH_TYPE_RANGE:
      return 2 * nbytes;
    default:
      assert(0);
  }
}

size_t get_match_key_size(const pi_p4info_t *p4info, pi_p4_id_t table_id);
size_t get_action_data_size(const pi_p4info_t *p4info, pi_p4_id_t action_id);

struct pi_match_key_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t table_id;
  size_t data_size;
  char *data;
};

struct pi_action_data_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t action_id;
  size_t data_size;
  char *data;
};

struct pi_table_fetch_res_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t table_id;  // TODO(antonin): remove?
  size_t num_entries;
  size_t mkey_nbytes;
  size_t idx;
  size_t curr;
  size_t entries_size;
  char *entries;
  // just pointers to entries byte array
  struct pi_match_key_s *match_keys;
  struct pi_action_data_s *action_datas;
  struct pi_entry_properties_s *properties;
  // direct resources
};

const pi_p4info_t *pi_get_device_p4info(uint16_t dev_id);

#ifdef __cplusplus
}
#endif

#endif  // PI_INT_PI_INT_H_
