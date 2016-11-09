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
//! Functions to query header field information in a p4info object.

#ifndef PI_INC_PI_P4INFO_FIELDS_H_
#define PI_INC_PI_P4INFO_FIELDS_H_

#include "PI/pi_base.h"

#ifdef __cplusplus
extern "C" {
#endif

pi_p4_id_t pi_p4info_field_id_from_name(const pi_p4info_t *p4info,
                                        const char *name);

const char *pi_p4info_field_name_from_id(const pi_p4info_t *p4info,
                                         pi_p4_id_t field_id);

size_t pi_p4info_field_bitwidth(const pi_p4info_t *p4info, pi_p4_id_t field_id);

char pi_p4info_field_byte0_mask(const pi_p4info_t *p4info, pi_p4_id_t field_id);

pi_p4_id_t pi_p4info_field_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_field_next(const pi_p4info_t *p4info, pi_p4_id_t id);
pi_p4_id_t pi_p4info_field_end(const pi_p4info_t *p4info);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_P4INFO_FIELDS_H_
