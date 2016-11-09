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
//! Includes the p4info headers for all standard resource types, for
//! convenience.

#ifndef PI_INC_PI_PI_P4INFO_H_
#define PI_INC_PI_PI_P4INFO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "pi_base.h"
#include "p4info/actions.h"
#include "p4info/fields.h"
#include "p4info/tables.h"
#include "p4info/act_profs.h"
#include "p4info/counters.h"
#include "p4info/meters.h"
#include "p4info/field_list.h"

// TODO(antonin): hide in an internal header file?
pi_status_t pi_empty_config(pi_p4info_t **p4info);

//! Adds a config of a given type and initialize the corresponding \p p4info
//! object.
pi_status_t pi_add_config(const char *config, pi_config_type_t config_type,
                          pi_p4info_t **p4info);

//! Adds a config by from a file. Reads the file and calls pi_add_config.
pi_status_t pi_add_config_from_file(const char *config_path,
                                    pi_config_type_t config_type,
                                    pi_p4info_t **p4info);

//! Release the memory for a given \p p4info object.
pi_status_t pi_destroy_config(pi_p4info_t *p4info);

//! Serialize p4info in native PI JSON format. If \p fmt is 0, non-formatted,
//! else formatted.
char *pi_serialize_config(const pi_p4info_t *p4info, int fmt);

// generic iterators, to iterate over all types of resources, still a work in
// progress
pi_p4_id_t pi_p4info_any_begin(const pi_p4info_t *p4info,
                               pi_res_type_id_t type);
pi_p4_id_t pi_p4info_any_next(pi_p4_id_t id);
pi_p4_id_t pi_p4info_any_end(const pi_p4info_t *p4info, pi_res_type_id_t type);

size_t pi_p4info_any_num(const pi_p4info_t *p4info, pi_res_type_id_t type);
// TODO(antonin): why do I need type, it is in id...
const char *pi_p4info_any_name_from_id(const pi_p4info_t *p4info,
                                       pi_res_type_id_t type, pi_p4_id_t id);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_P4INFO_H_
