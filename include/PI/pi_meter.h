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

#ifndef PI_INC_PI_PI_METER_H_
#define PI_INC_PI_PI_METER_H_

#include <PI/pi_base.h>
#include <PI/pi_tables.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  //! default is as per the P4 program
  PI_METER_UNIT_DEFAULT = 0,
  PI_METER_UNIT_PACKETS = 1,
  PI_METER_UNIT_BYTES = 2,
} pi_meter_unit_t;

typedef enum {
  //! default is as per the P4 program
  PI_METER_TYPE_DEFAULT = 0,
  PI_METER_TYPE_COLOR_AWARE = 1,
  PI_METER_TYPE_COLOR_UNAWARE = 2,
} pi_meter_type_t;

//! Configuration for a 2-rate 3-color marker, as per RFC 2698
typedef struct {
  //! Committed information rate (units per sec)
  uint64_t cir;
  //! Committed burst size
  uint32_t cburst;
  //! Peak information rate (units per sec)
  uint64_t pir;
  //! Peak burst size
  uint32_t pburst;
  //! Meter unit (bytes / packets)
  pi_meter_unit_t meter_unit;
  //! Meter type (color-awareness)
  pi_meter_type_t meter_type;
} pi_meter_spec_t;

//! Reads an indirect meter configuration at the given \p index.
pi_status_t pi_meter_read(pi_session_handle_t session_handle,
                          pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                          size_t index, pi_meter_spec_t *meter_spec);

//! Sets an indirect meter configuration at the given \p index.
pi_status_t pi_meter_set(pi_session_handle_t session_handle,
                         pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                         size_t index, const pi_meter_spec_t *meter_spec);

//! Reads the direct meter configuration for the given \p entry_handle.
pi_status_t pi_meter_read_direct(pi_session_handle_t session_handle,
                                 pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                 pi_entry_handle_t entry_handle,
                                 pi_meter_spec_t *meter_spec);

//! Sets the direct meter configuration for the given \p entry_handle.
pi_status_t pi_meter_set_direct(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                pi_entry_handle_t entry_handle,
                                const pi_meter_spec_t *meter_spec);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_METER_H_
