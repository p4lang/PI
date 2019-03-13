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
#include <memory>
#include <unordered_map>

#include "pi-bmv2-config.h"

#ifdef PI_BMV2_HAVE_THRIFT_STDCXX_H
#include <thrift/stdcxx.h>
namespace stdcxx = ::apache::thrift::stdcxx;
#else
namespace stdcxx = boost;
#endif

using namespace ::apache::thrift;  // NOLINT(build/namespaces)
using namespace ::apache::thrift::protocol;  // NOLINT(build/namespaces)
using namespace ::apache::thrift::transport;  // NOLINT(build/namespaces)

namespace pibmv2 {

struct ClientImp {
  ::stdcxx::shared_ptr<TTransport> transport{nullptr};
  std::unique_ptr<StandardClient> client{nullptr};
  std::unique_ptr<SimplePreLAGClient> mc_client{nullptr};
  std::mutex mutex{};
};

struct conn_mgr_t {
  std::unordered_map<dev_id_t, ClientImp> clients;
};

conn_mgr_t *conn_mgr_create() {
  conn_mgr_t *conn_mgr_state = new conn_mgr_t();
  return conn_mgr_state;
}

void conn_mgr_destroy(conn_mgr_t *conn_mgr_state) {
  // close connections?
  delete conn_mgr_state;
}

int conn_mgr_client_init(conn_mgr_t *conn_mgr_state, dev_id_t dev_id,
                         int thrift_port_num) {
  assert(conn_mgr_state->clients.find(dev_id) == conn_mgr_state->clients.end());
  auto &client = conn_mgr_state->clients[dev_id];  // construct

  ::stdcxx::shared_ptr<TTransport> socket(
      new TSocket("localhost", thrift_port_num));
  ::stdcxx::shared_ptr<TTransport> transport(new TBufferedTransport(socket));
  ::stdcxx::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

  ::stdcxx::shared_ptr<TMultiplexedProtocol> standard_protocol(
      new TMultiplexedProtocol(protocol, "standard"));
  ::stdcxx::shared_ptr<TMultiplexedProtocol> mc_protocol(
      new TMultiplexedProtocol(protocol, "simple_pre_lag"));

  try {
    transport->open();
  }
  catch (TException& tx) {
    std::cout << "Could not connect to port " << thrift_port_num
              << "(device " << dev_id << ")" << std::endl;

    return 1;
  }

  client.transport = transport;
  client.client = std::unique_ptr<StandardClient>(
      new StandardClient(standard_protocol));
  client.mc_client = std::unique_ptr<SimplePreLAGClient>(
      new SimplePreLAGClient(mc_protocol));

  return 0;
}

int conn_mgr_client_close(conn_mgr_t *conn_mgr_state, dev_id_t dev_id) {
  auto it = conn_mgr_state->clients.find(dev_id);
  assert(it != conn_mgr_state->clients.end());
  auto &client = it->second;
  client.transport->close();
  conn_mgr_state->clients.erase(it);
  return 0;
}

Client conn_mgr_client(conn_mgr_t *conn_mgr_state, dev_id_t dev_id) {
  auto &state = conn_mgr_state->clients[dev_id];
  return {state.client.get(), std::unique_lock<std::mutex>(state.mutex)};
}

McClient conn_mgr_mc_client(conn_mgr_t *conn_mgr_state, dev_id_t dev_id) {
  auto &state = conn_mgr_state->clients[dev_id];
  return {state.mc_client.get(), std::unique_lock<std::mutex>(state.mutex)};
}


}  // namespace pibmv2
