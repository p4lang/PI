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

#ifndef PI_INC_PI_PI_COUNTER_H_
#define PI_INC_PI_PI_COUNTER_H_

#include <PI/pi_base.h>
#include <PI/pi_tables.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t pi_counter_value_t;

#define PI_COUNTER_UNIT_PACKETS (1 << 0)
#define PI_COUNTER_UNIT_BYTES (1 << 1)

typedef struct {
  //! member validity: packets, bytes or both?
  int valid;
  pi_counter_value_t bytes;
  pi_counter_value_t packets;
} pi_counter_data_t;

#define PI_COUNTER_FLAGS_NONE 0
// do a sync with the hw when reading a counter
#define PI_COUNTER_FLAGS_HW_SYNC (1 << 0)

//! Reads an indirect counter at the given \p index.
pi_status_t pi_counter_read(pi_session_handle_t session_handle,
                            pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                            size_t index, int flags,
                            pi_counter_data_t *counter_data);

//! Writes an indirect counter at the given \p index.
pi_status_t pi_counter_write(pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                             size_t index,
                             const pi_counter_data_t *counter_data);

//! Reads the direct counter for the given \p entry_handle.
pi_status_t pi_counter_read_direct(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                   pi_entry_handle_t entry_handle, int flags,
                                   pi_counter_data_t *counter_data);

//! Writes the direct counter for the given \p entry_handle.
pi_status_t pi_counter_write_direct(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                    pi_entry_handle_t entry_handle,
                                    const pi_counter_data_t *counter_data);

//! Callback type for hw sync
typedef void (*PICounterHwSyncCb)(pi_dev_id_t dev_id, pi_p4_id_t counter_id,
                                  void *cb_cookie);

//! Sync all counter array entries with hardware. Use NULL for \p cb for
//! blocking call.
pi_status_t pi_counter_hw_sync(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                               PICounterHwSyncCb cb, void *cb_cookie);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_COUNTER_H_
