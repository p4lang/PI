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

typedef union {
  char bytes[8];
  uint64_t v;
  char *more_bytes;
} _compact_v_t;

struct pi_match_key_s {
  pi_p4_id_t table_id;
  uint32_t nset;
  _compact_v_t data[];
};

struct pi_action_data_s {
  pi_p4_id_t action_id;
  _compact_v_t data[];
};

struct pi_entry_properties_s {
  uint32_t valid_properties;
  uint32_t priority;
  uint32_t ttl;
};

struct pi_table_retrive_res_s {
  int dummy;
};

const pi_p4info_t *pi_get_device_p4info(uint16_t dev_id);

#endif  // PI_SRC_PI_INT_H_
