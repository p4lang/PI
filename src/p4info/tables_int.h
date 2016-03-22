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

#ifndef PI_SRC_P4INFO_TABLES_INT_H_
#define PI_SRC_P4INFO_TABLES_INT_H_

#include "PI/p4info/tables.h"

void pi_p4info_table_init(pi_p4info_t *p4info, size_t num_tables);

void pi_p4info_table_free(pi_p4info_t *p4info);

void pi_p4info_table_add(pi_p4info_t *p4info, pi_p4_id_t table_id,
                         const char *name, size_t num_match_fields,
                         size_t num_actions);

void pi_p4info_table_add_match_field(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                     pi_p4_id_t field_id, const char *name,
                                     pi_p4info_match_type_t match_type,
                                     size_t bitwidth);

void pi_p4info_table_add_action(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                pi_p4_id_t action_id);

#endif  // PI_SRC_P4INFO_TABLES_INT_H_
