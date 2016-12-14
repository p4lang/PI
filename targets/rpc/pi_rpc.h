/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef PI_RPC_PI_RPC_H_
#define PI_RPC_PI_RPC_H_

#include <PI/int/pi_int.h>
#include <PI/int/rpc_common.h>
#include <PI/int/serialize.h>
#include <PI/pi.h>

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
