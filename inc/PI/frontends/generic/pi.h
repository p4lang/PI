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

#ifndef PI_INC_PI_FRONTENDS_GENERIC_PI_H_
#define PI_INC_PI_FRONTENDS_GENERIC_PI_H_

#include "PI/pi_base.h"

////////// MATCH KEY //////////

pi_status_t pi_match_key_init(const pi_p4_id_t table_id,
                              pi_match_key_t **key);

pi_status_t pi_match_key_exact_set(pi_match_key_t *key,
                                   pi_p4_id_t field_id,
                                   const pi_value_t *value);

pi_status_t pi_match_key_lpm_set(pi_match_key_t *key,
                                 pi_p4_id_t field_id,
                                 const pi_value_t *value,
                                 const pi_prefix_length_t prefix_length);

pi_status_t pi_match_key_ternary_set(pi_match_key_t *key,
                                     pi_p4_id_t field_id,
                                     const pi_value_t *value,
                                     const pi_value_t *mask);

pi_status_t pi_match_key_range_set(pi_match_key_t *key,
                                   pi_p4_id_t field_id,
                                   const pi_value_t *start,
                                   const pi_value_t *end);

pi_status_t pi_match_key_destroy(pi_match_key_t *key);

////////// ACTION DATA //////////

// same remarks as for the field_id_t above

pi_status_t pi_action_data_init(const pi_p4_id_t action_id,
                                pi_action_data_t *action_data);

pi_status_t pi_action_data_arg_set(pi_action_data_t *action_data,
                                   pi_p4_id_t param_id,
                                   const pi_value_t *value);

pi_status_t pi_action_data_destroy(pi_action_data_t *action_data);

#endif  // PI_INC_PI_FRONTENDS_GENERIC_PI_H_
