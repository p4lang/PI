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
//! Functions to query action information in a p4info object.

#ifndef PI_INC_PI_P4INFO_ACTIONS_H_
#define PI_INC_PI_P4INFO_ACTIONS_H_

#include "PI/pi_base.h"

size_t pi_p4info_action_get_num(const pi_p4info_t *p4info);

pi_p4_id_t pi_p4info_action_id_from_name(const pi_p4info_t *p4info,
                                         const char *name);

const char *pi_p4info_action_name_from_id(const pi_p4info_t *p4info,
                                          pi_p4_id_t action_id);

size_t pi_p4info_action_num_params(const pi_p4info_t *p4info,
                                   pi_p4_id_t action_id);

const pi_p4_id_t *pi_p4info_action_get_params(const pi_p4info_t *p4info,
                                              pi_p4_id_t action_id,
                                              size_t *num_params);

pi_p4_id_t pi_p4info_action_param_id_from_name(const pi_p4info_t *p4info,
                                               pi_p4_id_t action_id,
                                               const char *name);

const char *pi_p4info_action_param_name_from_id(const pi_p4info_t *p4info,
                                                pi_p4_id_t param_id);

size_t pi_p4info_action_param_bitwidth(const pi_p4info_t *p4info,
                                       pi_p4_id_t param_id);

char pi_p4info_action_param_byte0_mask(const pi_p4info_t *p4info,
                                       pi_p4_id_t param_id);

size_t pi_p4info_action_param_offset(const pi_p4info_t *p4info,
                                     pi_p4_id_t param_id);

pi_p4_id_t pi_p4info_action_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_action_next(const pi_p4info_t *p4info, pi_p4_id_t id);
pi_p4_id_t pi_p4info_action_end(const pi_p4info_t *p4info);

#endif  // PI_INC_PI_P4INFO_ACTIONS_H_
