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

#ifndef PI_RPC_PI_RPC_H_
#define PI_RPC_PI_RPC_H_

#include <PI/pi.h>
#include <PI/int/pi_int.h>
#include <PI/int/serialize.h>
#include <PI/int/rpc_common.h>

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

typedef struct {
  int init;
  pi_rpc_id_t req_id;
  int s;
} pi_rpc_state_t;

extern char *rpc_addr;
extern char *notifications_addr;

extern pi_rpc_state_t state;

pi_status_t retrieve_rep_hdr(const char *rep, pi_rpc_id_t req_id);

pi_status_t wait_for_status(pi_rpc_id_t req_id);

size_t emit_req_hdr(char *hdr, pi_rpc_id_t id, pi_rpc_type_t type);

#endif  // PI_RPC_PI_RPC_H_
