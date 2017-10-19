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

#include "conn_mgr.h"

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/protocol/TMultiplexedProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>

#include <iostream>

namespace pibmv2 {

#define NUM_DEVICES 256

using namespace ::apache::thrift;  // NOLINT(build/namespaces)
using namespace ::apache::thrift::protocol;  // NOLINT(build/namespaces)
using namespace ::apache::thrift::transport;  // NOLINT(build/namespaces)

struct ClientImp {
  StandardClient *client{nullptr};
  SimplePreLAGClient *mc_client{nullptr};
  SimpleSwitchClient *sswitch_client{nullptr};
  std::mutex mutex{};
};

struct conn_mgr_t {
  std::array<ClientImp, NUM_DEVICES> clients;
  boost::shared_ptr<TTransport> transports[NUM_DEVICES];
};

conn_mgr_t *conn_mgr_create() {
  conn_mgr_t *conn_mgr_state = new conn_mgr_t();
  return conn_mgr_state;
}

void conn_mgr_destroy(conn_mgr_t *conn_mgr_state) {
  // close connections?
  delete conn_mgr_state;
}

int conn_mgr_client_init(conn_mgr_t *conn_mgr_state, int dev_id,
                         int thrift_port_num) {
  assert(!conn_mgr_state->clients[dev_id].client);

  boost::shared_ptr<TTransport> socket(
      new TSocket("localhost", thrift_port_num));
  boost::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
  boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

  boost::shared_ptr<TMultiplexedProtocol> standard_protocol(
      new TMultiplexedProtocol(protocol, "standard"));
  boost::shared_ptr<TMultiplexedProtocol> mc_protocol(
      new TMultiplexedProtocol(protocol, "simple_pre_lag"));
  boost::shared_ptr<TMultiplexedProtocol> sswitch_protocol(
      new TMultiplexedProtocol(protocol, "simple_switch"));

  try {
    transport->open();
  }
  catch (TException& tx) {
    std::cout << "Could not connect to port " << thrift_port_num
              << "(device " << dev_id << ")" << std::endl;

    return 1;
  }

  conn_mgr_state->transports[dev_id] = transport;
  conn_mgr_state->clients[dev_id].client =
      new StandardClient(standard_protocol);
  conn_mgr_state->clients[dev_id].mc_client =
      new SimplePreLAGClient(mc_protocol);

  return 0;
}

int conn_mgr_client_close(conn_mgr_t *conn_mgr_state, int dev_id) {
  assert(conn_mgr_state->clients[dev_id].client);
  conn_mgr_state->transports[dev_id]->close();
  delete conn_mgr_state->clients[dev_id].client;
  delete conn_mgr_state->clients[dev_id].mc_client;
  delete conn_mgr_state->clients[dev_id].sswitch_client;
  conn_mgr_state->clients[dev_id].client = NULL;
  conn_mgr_state->clients[dev_id].mc_client = NULL;
  conn_mgr_state->clients[dev_id].sswitch_client = NULL;
  return 0;
}

Client conn_mgr_client(conn_mgr_t *conn_mgr_state, int dev_id) {
  auto &state = conn_mgr_state->clients[dev_id];
  return {state.client, std::unique_lock<std::mutex>(state.mutex)};
}

McClient conn_mgr_mc_client(conn_mgr_t *conn_mgr_state, int dev_id) {
  auto &state = conn_mgr_state->clients[dev_id];
  return {state.mc_client, std::unique_lock<std::mutex>(state.mutex)};
}


}  // namespace pibmv2
