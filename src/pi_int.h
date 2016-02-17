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

struct pi_match_key_s {
  pi_table_id_t table_id;
  pi_value_t data[1];
};

struct pi_action_data_s {
  pi_action_id_t action_id;
  pi_value_t data[1];
};

struct pi_entry_properties_s {
  uint32_t valid_properties;
  uint32_t priority;
  uint32_t ttl;
};

struct pi_table_retrive_res_s {
  int dummy;
};

#endif  // PI_SRC_PI_INT_H_
