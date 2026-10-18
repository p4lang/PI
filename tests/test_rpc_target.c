/* SPDX-FileCopyrightText: 2026 The P4 Language Consortium & Devansh Singh
 * SPDX-License-Identifier: Apache-2.0
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

#include "PI/int/rpc_common.h"
#include "PI/int/serialize.h"
#include "PI/pi.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include "unity/unity_fixture.h"

// a minimal server always replying SUCCESS is enough to test request building

static char rpc_addr[256];
static char *ipc_path;

static volatile int server_ready = 0;
static volatile int server_shutdown = 0;

static void serve_request(int s) {
  char *req = NULL;
  int bytes = nn_recv(s, &req, NN_MSG, NN_DONTWAIT);
  if (bytes == -1 && errno == EAGAIN) return;
  assert(bytes > 0);

  uint32_t req_id;
  uint32_t req_type;
  const char *req_ = req;
  req_ += retrieve_uint32(req_, &req_id);
  req_ += retrieve_uint32(req_, &req_type);

  char rep[sizeof(rep_hdr_t) + sizeof(uint32_t)];
  char *rep_ = rep;
  rep_ += emit_uint32(rep_, req_id);
  rep_ += emit_status(rep_, PI_STATUS_SUCCESS);
  // PI_RPC_INIT replies append the list of configured devices, empty here
  if (req_type == PI_RPC_INIT) rep_ += emit_uint32(rep_, 0u);

  int rc = nn_send(s, rep, rep_ - rep, 0);
  assert((size_t)rc == (size_t)(rep_ - rep));

  nn_freemsg(req);

  if (req_type == PI_RPC_DESTROY) server_shutdown = 1;
}

static void *server_run(void *arg) {
  (void)arg;
  int s = nn_socket(AF_SP, NN_REP);
  assert(s >= 0);
  int rc = nn_bind(s, rpc_addr);
  assert(rc >= 0);
  server_ready = 1;
  while (!server_shutdown) {
    serve_request(s);
    if (!server_shutdown) usleep(10000);
  }
  nn_close(s);
  return NULL;
}

TEST_GROUP(RpcTarget);

static pthread_t server_thread;

TEST_SETUP(RpcTarget) {
  snprintf(rpc_addr, sizeof(rpc_addr), "ipc:///tmp/pi_rpc_test_%d.ipc",
           (int)getpid());
  ipc_path = rpc_addr + strlen("ipc://");
  server_ready = 0;
  server_shutdown = 0;
  int rc = pthread_create(&server_thread, NULL, server_run, NULL);
  TEST_ASSERT_EQUAL(0, rc);
  while (!server_ready) usleep(1000);
}

TEST_TEAR_DOWN(RpcTarget) {
  server_shutdown = 1;
  pthread_join(server_thread, NULL);
  unlink(ipc_path);
}

TEST(RpcTarget, AssignDeviceNullExtras) {
  pi_remote_addr_t remote_addr;
  remote_addr.rpc_addr = rpc_addr;
  remote_addr.notifications_addr = NULL;
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_init(256, &remote_addr));
  // this used to crash when building the request, p4info may also be NULL
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_assign_device(1, NULL, NULL));
  // a valid array with a NULL value for the last element skips every extra
  pi_assign_extra_t extras[2] = {
    {0, "cpu_iface", "veth0"},
    {1, NULL, NULL},
  };
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_assign_device(2, NULL, extras));
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy());
}

TEST_GROUP_RUNNER(RpcTarget) {
  RUN_TEST_CASE(RpcTarget, AssignDeviceNullExtras);
}

void test_rpc_target() { RUN_TEST_GROUP(RpcTarget); }
