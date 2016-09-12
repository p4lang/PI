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

#ifndef PI_SRC_P4INFO_COUNTERS_INT_H_
#define PI_SRC_P4INFO_COUNTERS_INT_H_

#include "PI/p4info/counters.h"

void pi_p4info_counter_init(pi_p4info_t *p4info, size_t num_counters);

void pi_p4info_counter_add(pi_p4info_t *p4info, pi_p4_id_t counter_id,
                           const char *name,
                           pi_p4info_counter_unit_t counter_unit, size_t size);

void pi_p4info_counter_make_direct(pi_p4info_t *p4info, pi_p4_id_t counter_id,
                                   pi_p4_id_t direct_table_id);

typedef struct cJSON cJSON;
void pi_p4info_counter_serialize(cJSON *root, const pi_p4info_t *p4info);

#endif  // PI_SRC_P4INFO_COUNTERS_INT_H_
