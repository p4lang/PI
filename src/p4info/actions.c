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

#include "PI/p4info/actions.h"

pi_p4_id_t pi_p4info_action_id_from_name(const char *name) {
  (void) name;
  return 0;
}

const char *pi_p4info_action_name_from_id(pi_p4_id_t action_id) {
  (void) action_id;
  return NULL;
}

size_t pi_p4info_action_num_params(pi_p4_id_t action_id) {
  (void) action_id;
  return 0;
}

const pi_p4_id_t *pi_p4info_action_get_params(pi_p4_id_t action_id,
                                              size_t *num_params) {
  (void) action_id; (void) num_params;
  return NULL;
}

pi_p4_id_t pi_p4info_action_param_id_from_name(const char *name) {
  (void) name;
  return 0;
}

bool pi_p4info_action_is_param_of(pi_p4_id_t action_id, pi_p4_id_t param_id) {
  (void) action_id; (void) param_id;
  return false;
}
