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

#ifndef PI_INC_PI_PI_H_
#define PI_INC_PI_PI_H_

#include "pi_base.h"
#include "pi_tables.h"
#include "pi_act_prof.h"
#include "pi_counter.h"
#include "pi_meter.h"

#ifdef __cplusplus
extern "C" {
#endif

//! Returns the P4 config (p4info) associated with that device id, NULL if the
//! device is not assigned.
const pi_p4info_t *pi_get_device_p4info(pi_dev_id_t dev_id);

//! Addresses for RPC server and notifications server (PUBSUB)
typedef struct {
  char *rpc_addr;
  char *notifications_addr;
} pi_remote_addr_t;

//! Init function for PI
pi_status_t pi_init(size_t max_devices, pi_remote_addr_t *remote_addr);

typedef struct {
  int end_of_extras;
  const char *key;
  const char *v;
} pi_assign_extra_t;

//! Assigns a P4 config to a device. Different targets may need different
//! indormation at that stage, so arbitary parameters can be provided using \p
//! extra.
pi_status_t pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                             pi_assign_extra_t *extra);

//! Inititate a P4 config update on a device. After this function is called,
//! packets will still be processed by the target using the old config, but all
//! PI calls (e.g. table updates) will apply to the new config. When you are
//! ready to swap configs at the target, call pi_update_device_end. Different
//! target may need a different input at that stage, which is what \p
//! device_data is for.
pi_status_t pi_update_device_start(pi_dev_id_t dev_id,
                                   const pi_p4info_t *p4info,
                                   const char *device_data,
                                   size_t device_data_size);

//! Terminates a P4 config update sequence, see pi_update_device_start.
pi_status_t pi_update_device_end(pi_dev_id_t dev_id);

//! Remove a device.
pi_status_t pi_remove_device(pi_dev_id_t dev_id);

//! Init a client session.
pi_status_t pi_session_init(pi_session_handle_t *session_handle);

//! Terminate a client session.
pi_status_t pi_session_cleanup(pi_session_handle_t session_handle);

//! PI cleanup function.
pi_status_t pi_destroy();

//! Callback type for packet-in.
typedef void (*PIPacketInCb)(pi_dev_id_t dev_id, const char *pkt, size_t size,
                             void *cb_cookie);
//! Register a callback for packet-in events, for a given device.
pi_status_t pi_packetin_register_cb(pi_dev_id_t dev_id, PIPacketInCb cb,
                                    void *cb_cookie);
//! Register a default callback for packet-in, which will be used if no specific
//! callback was specified for the device which issued the packet-in event.
pi_status_t pi_packetin_register_default_cb(PIPacketInCb cb, void *cb_cookie);
//! De-register a packet-in callback for a given device
pi_status_t pi_packetin_deregister_cb(pi_dev_id_t dev_id);
//! De-register default callback.
pi_status_t pi_packetin_deregister_default_cb();

//! Inject a packet in the specified device.
pi_status_t pi_packetout_send(pi_dev_id_t dev_id, const char *pkt, size_t size);

// TODO(antonin): move this to pi_tables?
// When adding a table entry, the configuration for direct resources associated
// with the entry can be provided. The config is then passed as a generic void *
// pointer. For the sake of the messaging system, we need a way to seriralize /
// de-serialize the config, thus the need for these:
// size when serialized
typedef size_t (*PIDirectResMsgSizeFn)(const void *config);
// emit function for serialization
typedef size_t (*PIDirectResEmitFn)(char *dst, const void *config);
// retrieve function for de-serialization
typedef size_t (*PIDirectResRetrieveFn)(const char *src, void *config);
// size_of is the size of memory blob required by retrieve function, alignment
// is guaranteed to be maximum for the architecture (e.g. 16 bytes for x86_64)
pi_status_t pi_direct_res_register(pi_res_type_id_t res_type,
                                   PIDirectResMsgSizeFn msg_size_fn,
                                   PIDirectResEmitFn emit_fn, size_t size_of,
                                   PIDirectResRetrieveFn retrieve_fn);

// set ptr to NULL if not interested
pi_status_t pi_direct_res_get_fns(pi_res_type_id_t res_type,
                                  PIDirectResMsgSizeFn *msg_size_fn,
                                  PIDirectResEmitFn *emit_fn, size_t *size_of,
                                  PIDirectResRetrieveFn *retrieve_fn);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_H_
