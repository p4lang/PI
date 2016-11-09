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

//! @file
//! Functions to query table information in a p4info object.

#ifndef PI_INC_PI_P4INFO_TABLES_H_
#define PI_INC_PI_P4INFO_TABLES_H_

#include "PI/pi_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  PI_P4INFO_MATCH_TYPE_VALID = 0,
  PI_P4INFO_MATCH_TYPE_EXACT,
  PI_P4INFO_MATCH_TYPE_LPM,
  PI_P4INFO_MATCH_TYPE_TERNARY,
  PI_P4INFO_MATCH_TYPE_RANGE,
  PI_P4INFO_MATCH_TYPE_END
} pi_p4info_match_type_t;

typedef struct {
  const char *name;
  pi_p4_id_t field_id;
  pi_p4info_match_type_t match_type;
  size_t bitwidth;
} pi_p4info_match_field_info_t;

pi_p4_id_t pi_p4info_table_id_from_name(const pi_p4info_t *p4info,
                                        const char *name);

const char *pi_p4info_table_name_from_id(const pi_p4info_t *p4info,
                                         pi_p4_id_t table_id);

size_t pi_p4info_table_num_match_fields(const pi_p4info_t *p4info,
                                        pi_p4_id_t table_id);

const pi_p4_id_t *pi_p4info_table_get_match_fields(const pi_p4info_t *p4info,
                                                   pi_p4_id_t table_id,
                                                   size_t *num_match_fields);

bool pi_p4info_table_is_match_field_of(const pi_p4info_t *p4info,
                                       pi_p4_id_t table_id,
                                       pi_p4_id_t field_id);

size_t pi_p4info_table_match_field_index(const pi_p4info_t *p4info,
                                         pi_p4_id_t table_id,
                                         pi_p4_id_t field_id);

size_t pi_p4info_table_match_field_offset(const pi_p4info_t *p4info,
                                          pi_p4_id_t table_id,
                                          pi_p4_id_t field_id);

void pi_p4info_table_match_field_info(const pi_p4info_t *p4info,
                                      pi_p4_id_t table_id, size_t index,
                                      pi_p4info_match_field_info_t *info);

size_t pi_p4info_table_num_actions(const pi_p4info_t *p4info,
                                   pi_p4_id_t table_id);

bool pi_p4info_table_is_action_of(const pi_p4info_t *p4info,
                                  pi_p4_id_t table_id, pi_p4_id_t action_id);

const pi_p4_id_t *pi_p4info_table_get_actions(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id,
                                              size_t *num_actions);

bool pi_p4info_table_has_const_default_action(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id);
pi_p4_id_t pi_p4info_table_get_const_default_action(const pi_p4info_t *p4info,
                                                    pi_p4_id_t table_id);

pi_p4_id_t pi_p4info_table_get_implementation(const pi_p4info_t *p4info,
                                              pi_p4_id_t table_id);

bool pi_p4info_table_is_direct_resource_of(const pi_p4info_t *p4info,
                                           pi_p4_id_t table_id,
                                           pi_p4_id_t direct_res_id);

const pi_p4_id_t *pi_p4info_table_get_direct_resources(
    const pi_p4info_t *p4info, pi_p4_id_t table_id,
    size_t *num_direct_resources);

pi_p4_id_t pi_p4info_table_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_table_next(const pi_p4info_t *p4info, pi_p4_id_t id);
pi_p4_id_t pi_p4info_table_end(const pi_p4info_t *p4info);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_P4INFO_TABLES_H_
