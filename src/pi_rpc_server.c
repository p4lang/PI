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

#include "PI/target/pi_imp.h"
#include "PI/target/pi_tables_imp.h"
#include "PI/int/serialize.h"
#include "PI/int/rpc_common.h"

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include <stdio.h>

typedef struct {
  int init;
  uint32_t req_id;
  int s;
} pi_rpc_state_t;

static const char *addr = "ipc:///tmp/pi_rpc.ipc";

static pi_rpc_state_t state;

static void send_status(pi_status_t status) {
  typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t status;
  } msg_t;
  msg_t msg;
  char *msg_ = (char *) &msg;
  msg_ += emit_uint32(msg_, state.req_id);
  emit_uint32(msg_, status);
  int bytes = nn_send(state.s, &msg, sizeof(msg), 0);
  assert(bytes == sizeof(msg));
}

static void __pi_init(const char *msg) {
  (void) msg;
  send_status(PI_STATUS_SUCCESS);
}

static void __pi_assign_device(const char *msg) {
  (void) msg;
  send_status(PI_STATUS_SUCCESS);
}

static void __pi_remove_device(const char *msg) {
  (void) msg;
  send_status(PI_STATUS_SUCCESS);
}

static void __pi_destroy(const char *msg) {
  (void) msg;
  send_status(PI_STATUS_SUCCESS);
}

pi_status_t pi_rpc_server_run() {
  assert(!state.init);
  state.s = nn_socket(AF_SP, NN_REP);
  if (state.s < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  if (nn_bind(state.s, addr) < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  state.init = 1;

  while (1) {
    char *msg = NULL;
    int bytes = nn_recv(state.s, &msg, NN_MSG, 0);
    if (bytes < 0) return PI_STATUS_RPC_TRANSPORT_ERROR;
    if (bytes == 0) continue;

    uint32_t type;
    const char *msg_ = msg;
    msg_ += retrieve_uint32(msg_, &state.req_id);
    printf("req_id: %u\n", state.req_id);
    msg_ += retrieve_uint32(msg_, &type);

    switch ((pi_rpc_msg_id_t) type) {
      case PI_RPC_INIT:
        __pi_init(msg_); break;
      case PI_RPC_ASSIGN_DEVICE:
        __pi_assign_device(msg_); break;
      case PI_RPC_REMOVE_DEVICE:
        __pi_remove_device(msg_); break;
      case PI_RPC_DESTROY:
        __pi_destroy(msg_); break;
        break;
      default:
        assert(0);
    }

    nn_freemsg(msg);
  }

  return PI_STATUS_SUCCESS;
}
