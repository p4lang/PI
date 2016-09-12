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

#include <PI/pi.h>
#include <PI/pi_meter.h>
#include <PI/target/pi_meter_imp.h>

static bool is_direct_meter(const pi_p4info_t *p4info, pi_p4_id_t meter_id) {
  return (pi_p4info_meter_get_direct(p4info, meter_id) != PI_INVALID_ID);
}

pi_status_t pi_meter_read(pi_session_handle_t session_handle,
                          pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                          size_t index, pi_meter_spec_t *meter_spec) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (is_direct_meter(p4info, meter_id)) return PI_STATUS_METER_IS_DIRECT;
  return _pi_meter_read(session_handle, dev_tgt, meter_id, index, meter_spec);
}

pi_status_t pi_meter_set(pi_session_handle_t session_handle,
                         pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                         size_t index, const pi_meter_spec_t *meter_spec) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (is_direct_meter(p4info, meter_id)) return PI_STATUS_METER_IS_DIRECT;
  pi_meter_spec_t new_spec = *meter_spec;
  if (meter_spec->meter_unit == PI_METER_UNIT_DEFAULT)
    new_spec.meter_unit = pi_p4info_meter_get_unit(p4info, meter_id);
  if (meter_spec->meter_type == PI_METER_TYPE_DEFAULT)
    new_spec.meter_type = pi_p4info_meter_get_type(p4info, meter_id);
  return _pi_meter_set(session_handle, dev_tgt, meter_id, index, &new_spec);
}

pi_status_t pi_meter_read_direct(pi_session_handle_t session_handle,
                                 pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                 pi_entry_handle_t entry_handle,
                                 pi_meter_spec_t *meter_spec) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (!is_direct_meter(p4info, meter_id)) return PI_STATUS_METER_IS_NOT_DIRECT;
  return _pi_meter_read_direct(session_handle, dev_tgt, meter_id, entry_handle,
                               meter_spec);
}

pi_status_t pi_meter_set_direct(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                pi_entry_handle_t entry_handle,
                                const pi_meter_spec_t *meter_spec) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (!is_direct_meter(p4info, meter_id)) return PI_STATUS_METER_IS_NOT_DIRECT;
  pi_meter_spec_t new_spec = *meter_spec;
  if (meter_spec->meter_unit == PI_METER_UNIT_DEFAULT)
    new_spec.meter_unit = pi_p4info_meter_get_unit(p4info, meter_id);
  if (meter_spec->meter_type == PI_METER_TYPE_DEFAULT)
    new_spec.meter_type = pi_p4info_meter_get_type(p4info, meter_id);
  return _pi_meter_set_direct(session_handle, dev_tgt, meter_id, entry_handle,
                              &new_spec);
}
