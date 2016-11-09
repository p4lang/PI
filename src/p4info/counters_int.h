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

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef PI_SRC_P4INFO_COUNTERS_INT_H_
#define PI_SRC_P4INFO_COUNTERS_INT_H_

#include "PI/p4info/counters.h"

#ifdef __cplusplus
extern "C" {
#endif

void pi_p4info_counter_init(pi_p4info_t *p4info, size_t num_counters);

void pi_p4info_counter_add(pi_p4info_t *p4info, pi_p4_id_t counter_id,
                           const char *name,
                           pi_p4info_counter_unit_t counter_unit, size_t size);

void pi_p4info_counter_make_direct(pi_p4info_t *p4info, pi_p4_id_t counter_id,
                                   pi_p4_id_t direct_table_id);

typedef struct cJSON cJSON;
void pi_p4info_counter_serialize(cJSON *root, const pi_p4info_t *p4info);

#ifdef __cplusplus
}
#endif

#endif  // PI_SRC_P4INFO_COUNTERS_INT_H_
