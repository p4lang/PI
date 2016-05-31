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

#ifndef PI_SRC_PI_INT_H_
#define PI_SRC_PI_INT_H_

#include "PI/pi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PI_ACTION_ID        0x01
#define PI_TABLE_ID         0x02
#define PI_ACTION_PARAM_ID  0x03
#define PI_FIELD_ID         0x04

inline pi_p4_id_t pi_make_action_id(uint16_t index) {
  return (PI_ACTION_ID << 24) | index;
}

inline pi_p4_id_t pi_make_table_id(uint16_t index) {
  return (PI_TABLE_ID << 24) | index;
}

inline pi_p4_id_t pi_make_action_param_id(pi_p4_id_t action_id, uint8_t index) {
  uint16_t action_index = action_id & 0xffff;
  return (PI_ACTION_PARAM_ID << 24) | (action_index << 8) | index;
}

inline pi_p4_id_t pi_make_field_id(uint16_t index) {
  return (PI_FIELD_ID << 24) | index;
}

#define PI_GET_TYPE_ID(id) (id >> 24)

union __compact_v_t {
  char bytes[8];
  uint64_t v;
  char *more_bytes;
  struct {
    uint32_t v1;
    uint32_t v2;
  };
};

typedef union __compact_v_t _compact_v_t;

struct pi_entry_properties_s {
  uint32_t valid_properties;
  uint32_t priority;
  uint32_t ttl;
};

struct pi_table_fetch_res_s {
  size_t num_entries;
  size_t idx;
  size_t curr;
  size_t num_match_fields;
  _compact_v_t *entries;
  struct pi_entry_properties_s *properties;
  // direct resources
};

const pi_p4info_t *pi_get_device_p4info(uint16_t dev_id);

#ifdef __cplusplus
}
#endif

#endif  // PI_SRC_PI_INT_H_
