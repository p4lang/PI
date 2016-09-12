/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

//! @file
//! Functions to query table information in a p4info object.

#ifndef PI_INC_PI_P4INFO_TABLES_H_
#define PI_INC_PI_P4INFO_TABLES_H_

#include "PI/pi_base.h"

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

#endif  // PI_INC_PI_P4INFO_TABLES_H_
