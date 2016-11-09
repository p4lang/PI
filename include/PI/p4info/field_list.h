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
//! Functions to query field list information in a p4info object.

#ifndef PI_INC_PI_P4INFO_FIELD_LIST_H_
#define PI_INC_PI_P4INFO_FIELD_LIST_H_

#include "PI/pi_base.h"

#ifdef __cplusplus
extern "C" {
#endif

size_t pi_p4info_field_list_get_num(const pi_p4info_t *p4info);

pi_p4_id_t pi_p4info_field_list_id_from_name(const pi_p4info_t *p4info,
                                             const char *name);

const char *pi_p4info_field_list_name_from_id(const pi_p4info_t *p4info,
                                              pi_p4_id_t field_list_id);

size_t pi_p4info_field_list_num_fields(const pi_p4info_t *p4info,
                                       pi_p4_id_t field_list_id);

const pi_p4_id_t *pi_p4info_field_list_get_fields(const pi_p4info_t *p4info,
                                                  pi_p4_id_t field_list_id,
                                                  size_t *num_fields);

pi_p4_id_t pi_p4info_field_list_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_field_list_next(const pi_p4info_t *p4info, pi_p4_id_t id);
pi_p4_id_t pi_p4info_field_list_end(const pi_p4info_t *p4info);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_P4INFO_FIELD_LIST_H_
