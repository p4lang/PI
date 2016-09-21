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
#include <PI/pi_counter.h>
#include <PI/target/pi_counter_imp.h>

static bool is_direct_counter(const pi_p4info_t *p4info,
                              pi_p4_id_t counter_id) {
  return (pi_p4info_counter_get_direct(p4info, counter_id) != PI_INVALID_ID);
}

pi_status_t pi_counter_read(pi_session_handle_t session_handle,
                            pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                            size_t index, int flags,
                            pi_counter_data_t *counter_data) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (is_direct_counter(p4info, counter_id)) return PI_STATUS_COUNTER_IS_DIRECT;
  return _pi_counter_read(session_handle, dev_tgt, counter_id, index, flags,
                          counter_data);
}

pi_status_t pi_counter_write(pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                             size_t index,
                             const pi_counter_data_t *counter_data) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (is_direct_counter(p4info, counter_id)) return PI_STATUS_COUNTER_IS_DIRECT;
  return _pi_counter_write(session_handle, dev_tgt, counter_id, index,
                           counter_data);
}

pi_status_t pi_counter_read_direct(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                   pi_entry_handle_t entry_handle, int flags,
                                   pi_counter_data_t *counter_data) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (!is_direct_counter(p4info, counter_id))
    return PI_STATUS_COUNTER_IS_NOT_DIRECT;
  return _pi_counter_read_direct(session_handle, dev_tgt, counter_id,
                                 entry_handle, flags, counter_data);
}

pi_status_t pi_counter_write_direct(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                    pi_entry_handle_t entry_handle,
                                    const pi_counter_data_t *counter_data) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (!is_direct_counter(p4info, counter_id))
    return PI_STATUS_COUNTER_IS_NOT_DIRECT;
  return _pi_counter_write_direct(session_handle, dev_tgt, counter_id,
                                  entry_handle, counter_data);
}

pi_status_t pi_counter_hw_sync(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                               PICounterHwSyncCb cb, void *cb_cookie) {
  return _pi_counter_hw_sync(session_handle, dev_tgt, counter_id, cb,
                             cb_cookie);
}
