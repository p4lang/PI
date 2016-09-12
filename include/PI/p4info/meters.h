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
//! Functions to query meter information in a p4info object.

#ifndef PI_INC_PI_P4INFO_METERS_H_
#define PI_INC_PI_P4INFO_METERS_H_

#include <PI/pi_base.h>

// same as their PI equivalent, without the default option
typedef enum {
  PI_P4INFO_METER_UNIT_PACKETS = 1,
  PI_P4INFO_METER_UNIT_BYTES = 2,
} pi_p4info_meter_unit_t;

typedef enum {
  PI_P4INFO_METER_TYPE_COLOR_AWARE = 1,
  PI_P4INFO_METER_TYPE_COLOR_UNAWARE = 2,
} pi_p4info_meter_type_t;

pi_p4_id_t pi_p4info_meter_id_from_name(const pi_p4info_t *p4info,
                                        const char *name);

const char *pi_p4info_meter_name_from_id(const pi_p4info_t *p4info,
                                         pi_p4_id_t meter_id);

pi_p4_id_t pi_p4info_meter_get_direct(const pi_p4info_t *p4info,
                                      pi_p4_id_t meter_id);

pi_p4info_meter_unit_t pi_p4info_meter_get_unit(const pi_p4info_t *p4info,
                                                pi_p4_id_t meter_id);

pi_p4info_meter_type_t pi_p4info_meter_get_type(const pi_p4info_t *p4info,
                                                pi_p4_id_t meter_id);

size_t pi_p4info_meter_get_size(const pi_p4info_t *p4info, pi_p4_id_t meter_id);

pi_p4_id_t pi_p4info_meter_begin(const pi_p4info_t *p4info);
pi_p4_id_t pi_p4info_meter_next(const pi_p4info_t *p4info, pi_p4_id_t id);
pi_p4_id_t pi_p4info_meter_end(const pi_p4info_t *p4info);

#endif  // PI_INC_PI_P4INFO_METERS_H_
