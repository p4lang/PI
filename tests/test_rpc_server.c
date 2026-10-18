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
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include "unity/unity_fixture.h"

// pi_rpc_server_run usually runs in the pi_rpc_server process, we run it in a
// thread and talk to it with a raw nanomsg client

extern pi_status_t pi_rpc_server_run(const pi_remote_addr_t *remote_addr);

// the smallest config accepted by the native JSON reader
static const char *native_json_config =
    "{"
    "  \"actions\": ["
    "    {\"name\": \"noop\", \"id\": 16777217, \"params\": []}"
    "  ],"
    "  \"tables\": [{"
    "    \"name\": \"t\","
    "    \"id\": 33554433,"
    "    \"match_fields\": [],"
    "    \"actions\": [{\"id\": 16777217, \"scope\": 0}],"
    "    \"max_size\": 1024,"
    "    \"is_const\": false"
    "  }],"
    "  \"act_profs\": [],"
    "  \"counters\": [],"
    "  \"direct_counters\": [],"
    "  \"meters\": [],"
    "  \"direct_meters\": [],"
    "  \"digests\": []"
    "}";

static char rpc_addr[256];
static char *ipc_path;

static void *server_run(void *arg) {
  pi_rpc_server_run((const pi_remote_addr_t *)arg);
  return NULL;
}

static void send_request(int s, uint32_t req_id, pi_rpc_type_t type,
                         const char *body, size_t body_size) {
  size_t s_ = sizeof(req_hdr_t) + body_size;
  char *req = nn_allocmsg(s_, 0);
  assert(req);
  char *req_ = req;
  req_ += emit_uint32(req_, req_id);
  req_ += emit_uint32(req_, type);
  if (body_size > 0) memcpy(req_, body, body_size);
  int rc = nn_send(s, &req, NN_MSG, 0);
  assert((size_t)rc == s_);
}

static char *recv_reply(int s, uint32_t exp_req_id, pi_status_t *status) {
  char *rep = NULL;
  int bytes = nn_recv(s, &rep, NN_MSG, 0);
  assert(bytes > 0);
  const char *rep_ = rep;
  uint32_t req_id;
  uint32_t status_;
  rep_ += retrieve_uint32(rep_, &req_id);
  rep_ += retrieve_uint32(rep_, &status_);
  assert(req_id == exp_req_id);
  *status = (pi_status_t)status_;
  return rep;
}

TEST_GROUP(RpcServer);

TEST_SETUP(RpcServer) {
  snprintf(rpc_addr, sizeof(rpc_addr), "ipc:///tmp/pi_rpc_server_test_%d.ipc",
           (int)getpid());
  ipc_path = rpc_addr + strlen("ipc://");
}

TEST_TEAR_DOWN(RpcServer) { unlink(ipc_path); }

TEST(RpcServer, StateSync) {
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_init(256, NULL));

  pi_remote_addr_t server_addr = {rpc_addr, NULL};
  // the server loop cannot be stopped, the thread stays blocked in nn_recv
  // until the process exits
  pthread_t server_thread;
  int rc = pthread_create(&server_thread, NULL, server_run, &server_addr);
  TEST_ASSERT_EQUAL(0, rc);
  usleep(100000);

  int s = nn_socket(AF_SP, NN_REQ);
  TEST_ASSERT_TRUE(s >= 0);
  TEST_ASSERT_TRUE(nn_connect(s, rpc_addr) >= 0);

  pi_status_t status;
  char *rep;

  // no device assigned yet
  send_request(s, 0, PI_RPC_INIT, NULL, 0);
  rep = recv_reply(s, 0, &status);
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, status);
  uint32_t num_devices;
  retrieve_uint32(rep + sizeof(rep_hdr_t), &num_devices);
  nn_freemsg(rep);
  TEST_ASSERT_EQUAL_UINT32(0u, num_devices);

  // assign one device with a valid config
  char req_body[8 + 1024];
  char *req_body_ = req_body;
  req_body_ += emit_dev_id(req_body_, 1u);
  memcpy(req_body_, native_json_config, strlen(native_json_config) + 1);
  req_body_ += strlen(native_json_config) + 1;
  req_body_ += emit_uint32(req_body_, 0u);  // no extras
  send_request(s, 1, PI_RPC_ASSIGN_DEVICE, req_body, req_body_ - req_body);
  rep = recv_reply(s, 1, &status);
  nn_freemsg(rep);
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, status);

  // a new client gets the current state, with the p4info of every device
  send_request(s, 2, PI_RPC_INIT, NULL, 0);
  rep = recv_reply(s, 2, &status);
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, status);
  const char *rep_ = rep + sizeof(rep_hdr_t);
  rep_ += retrieve_uint32(rep_, &num_devices);
  TEST_ASSERT_EQUAL_UINT32(1u, num_devices);
  pi_dev_id_t dev_id;
  uint32_t version;
  rep_ += retrieve_dev_id(rep_, &dev_id);
  rep_ += retrieve_uint32(rep_, &version);
  (void)version;
  TEST_ASSERT_EQUAL(1, (int)dev_id);
  const char *json = rep_;
  pi_p4info_t *p4info = NULL;
  // the client parses the config of every device with the native JSON reader
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS,
                    pi_add_config(json, PI_CONFIG_TYPE_NATIVE_JSON, &p4info));
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy_config(p4info));
  nn_freemsg(rep);

  nn_close(s);
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy());
}

TEST_GROUP_RUNNER(RpcServer) {
  RUN_TEST_CASE(RpcServer, StateSync);
}

void test_rpc_server() { RUN_TEST_GROUP(RpcServer); }
