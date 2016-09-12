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

#ifndef PI_INC_PI_PI_LEARN_H_
#define PI_INC_PI_PI_LEARN_H_

#include "pi_base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t pi_learn_msg_id_t;

//! A learn message.
typedef struct {
  pi_dev_tgt_t dev_tgt;
  pi_p4_id_t learn_id;
  pi_learn_msg_id_t msg_id;
  size_t num_entries;
  size_t entry_size;  // can be inferred from learn_id but easier to have here
  char *entries;
} pi_learn_msg_t;

//! Callback type for learn events.
typedef void (*PILearnCb)(pi_learn_msg_t *msg, void *cb_cookie);

// no session_handle for these APIs, do they need one?
// because none of these calls result to a backend driver call, I do not see why
// they would

//! Register a learn callback for a given device and a given field list
pi_status_t pi_learn_register_cb(pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                 PILearnCb cb, void *cb_cookie);

//! Default callback. Will be called if no callback registered for a given
//! device and a given field list.
pi_status_t pi_learn_register_default_cb(PILearnCb cb, void *cb_cookie);

//! De-register callback for given device and field list.
pi_status_t pi_learn_deregister_cb(pi_dev_id_t dev_id, pi_p4_id_t learn_id);

//! De-register default callback.
pi_status_t pi_learn_deregister_default_cb();

//! Ack a received learn message. This indicates to the target that you have
//! fully processed the message and that it can remove the message from its
//! duplicate filter (for example).
pi_status_t pi_learn_msg_ack(pi_session_handle_t session_handle,
                             pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                             pi_learn_msg_id_t msg_id);

//! Indicate taht you are done with the lean message and that any associated
//! memory can be released.
pi_status_t pi_learn_msg_done(pi_learn_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_LEARN_H_
