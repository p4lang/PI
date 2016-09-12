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

#ifndef PI_SRC_P4INFO_TABLES_INT_H_
#define PI_SRC_P4INFO_TABLES_INT_H_

#include "PI/p4info/tables.h"

void pi_p4info_table_init(pi_p4info_t *p4info, size_t num_tables);

void pi_p4info_table_add(pi_p4info_t *p4info, pi_p4_id_t table_id,
                         const char *name, size_t num_match_fields,
                         size_t num_actions);

void pi_p4info_table_add_match_field(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                     pi_p4_id_t field_id, const char *name,
                                     pi_p4info_match_type_t match_type,
                                     size_t bitwidth);

void pi_p4info_table_add_action(pi_p4info_t *p4info, pi_p4_id_t table_id,
                                pi_p4_id_t action_id);

void pi_p4info_table_set_implementation(pi_p4info_t *p4info,
                                        pi_p4_id_t table_id,
                                        pi_p4_id_t implementation);

void pi_p4info_table_set_const_default_action(pi_p4info_t *p4info,
                                              pi_p4_id_t table_id,
                                              pi_p4_id_t default_action_id);

void pi_p4info_table_add_direct_resource(pi_p4info_t *p4info,
                                         pi_p4_id_t table_id,
                                         pi_p4_id_t direct_res_id);

typedef struct cJSON cJSON;
void pi_p4info_table_serialize(cJSON *root, const pi_p4info_t *p4info);

#endif  // PI_SRC_P4INFO_TABLES_INT_H_
