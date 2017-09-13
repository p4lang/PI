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

#include <PI/frontends/proto/device_mgr.h>
#include <PI/frontends/proto/gnmi_mgr.h>

#include <PI/proto/pi_server.h>

#include <grpc++/grpc++.h>
// #include <grpc++/support/error_details.h>

#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>

#include "gnmi/gnmi.grpc.pb.h"
#include "google/rpc/code.pb.h"
#include "p4/p4runtime.grpc.pb.h"
#include "pi_server_testing.h"
#include "uint128.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::ServerReaderWriter;
using grpc::Status;
using grpc::StatusCode;

using pi::fe::proto::GnmiMgr;
using pi::fe::proto::DeviceMgr;

#define DEBUG

#ifdef DEBUG
#define ENABLE_SIMPLELOG true
#else
#define ENABLE_SIMPLELOG false
#endif

#define SIMPLELOG if (ENABLE_SIMPLELOG) std::cout

namespace pi {

namespace server {

namespace {

// Copied from
// https://github.com/grpc/grpc/blob/master/src/cpp/util/error_details.cc
// Cannot use libgrpc++_error_details, as the library includes
// generated code for google.rpc.Status which clashes with libpiproto
// TODO(unknown): find a solution
Status SetErrorDetails(const ::google::rpc::Status& from, grpc::Status* to) {
  using grpc::Status;
  using grpc::StatusCode;
  if (to == nullptr) {
    return Status(StatusCode::FAILED_PRECONDITION, "");
  }
  StatusCode code = StatusCode::UNKNOWN;
  if (from.code() >= StatusCode::OK && from.code() <= StatusCode::DATA_LOSS) {
    code = static_cast<StatusCode>(from.code());
  }
  *to = Status(code, from.message(), from.SerializeAsString());
  return Status::OK;
}

// DeviceMgr::Status == google::rpc::Status
grpc::Status to_grpc_status(const DeviceMgr::Status &from) {
  grpc::Status to;
  // auto conversion_status = grpc::SetErrorDetails(from, &to);
  auto conversion_status = SetErrorDetails(from, &to);
  // This can only fail if the second argument to SetErrorDetails is a nullptr,
  // which cannot be the case here
  assert(conversion_status.ok());
  return to;
}

grpc::Status no_pipeline_config_status() {
  return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                      "No forwarding pipeline config set for this device");
}

grpc::Status not_master_status() {
  return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Not master");
}

class ConfigMgrInstance {
 public:
  static GnmiMgr *get() {
    static GnmiMgr mgr;
    return &mgr;
  }
};

using StreamChannelReaderWriter = grpc::ServerReaderWriter<
  p4::StreamMessageResponse, p4::StreamMessageRequest>;

class ConnectionId {
 public:
  using Id = Uint128;

  static Id get() {
    auto &instance_ = instance();
    return instance_.current_id++;
  }

 private:
  ConnectionId()
      : current_id(0, 1) { }

  static ConnectionId &instance() {
    static ConnectionId instance;
    return instance;
  }

  Id current_id;
};

class Connection {
 public:
  static std::unique_ptr<Connection> make(const Uint128 &election_id,
                                          StreamChannelReaderWriter *stream,
                                          ServerContext *context) {
    (void) context;
    return std::unique_ptr<Connection>(
        new Connection(ConnectionId::get(), election_id, stream));
  }

  const ConnectionId::Id &connection_id() const { return connection_id_; }
  const Uint128 &election_id() const { return election_id_; }
  StreamChannelReaderWriter *stream() const { return stream_; }

  void set_election_id(const Uint128 &election_id) {
    election_id_ = election_id;
  }

 private:
  Connection(ConnectionId::Id connection_id, const Uint128 &election_id,
             StreamChannelReaderWriter *stream)
      : connection_id_(connection_id), election_id_(election_id),
        stream_(stream) { }

  ConnectionId::Id connection_id_{0};
  Uint128 election_id_{0};
  StreamChannelReaderWriter *stream_{nullptr};
};

class DeviceState {
 public:
  struct CompareConnections {
    bool operator()(const Connection *c1, const Connection *c2) const {
      return c1->election_id() > c2->election_id();
    }
  };
  using Connections = std::set<Connection *, CompareConnections>;

  static constexpr size_t max_connections = 16;

  explicit DeviceState(DeviceMgr::device_id_t device_id)
      : device_id(device_id) { }

  DeviceMgr *get_p4_mgr() {
    std::lock_guard<std::mutex> lock(m);
    return device_mgr.get();
  }

  DeviceMgr *get_or_add_p4_mgr() {
    std::lock_guard<std::mutex> lock(m);
    if (device_mgr == nullptr) device_mgr.reset(new DeviceMgr(device_id));
    return device_mgr.get();
  }

  void send_packet_in(p4::PacketIn *packet) const {
    std::lock_guard<std::mutex> lock(m);
    auto master = get_master();
    if (master == nullptr) return;
    auto stream = master->stream();
    p4::StreamMessageResponse response;
    response.set_allocated_packet(packet);
    stream->Write(response);
    response.release_packet();
  }

  Status add_connection(Connection *connection) {
    std::lock_guard<std::mutex> lock(m);
    if (connections.size() >= max_connections)
      return Status(StatusCode::RESOURCE_EXHAUSTED, "Too many connections");
    auto p = connections.insert(connection);
    if (!p.second) {
      return Status(StatusCode::INVALID_ARGUMENT,
                    "Election id already exists");
    }
    SIMPLELOG << "New connection\n";
    auto is_master = (p.first == connections.begin());
    if (is_master)
      notify_all();
    else
      notify_one(connection);
    return Status::OK;
  }

  Status update_connection(Connection *connection,
                           const Uint128 &new_election_id) {
    std::lock_guard<std::mutex> lock(m);
    if (connection->election_id() == new_election_id) return Status::OK;
    auto connection_it = connections.find(connection);
    assert(connection_it != connections.end());
    auto was_master = (connection_it == connections.begin());
    connections.erase(connection_it);
    connection->set_election_id(new_election_id);
    auto p = connections.insert(connection);
    if (!p.second) {
      return Status(StatusCode::INVALID_ARGUMENT,
                    "New election id already exists");
    }
    auto is_master = (p.first == connections.begin());
    auto master_changed = (is_master != was_master);
    if (master_changed)
      notify_all();
    else
      notify_one(connection);
    return Status::OK;
  }

  void cleanup_connection(Connection *connection) {
    std::lock_guard<std::mutex> lock(m);
    auto connection_it = connections.find(connection);
    assert(connection_it != connections.end());
    auto was_master = (connection_it == connections.begin());
    connections.erase(connection_it);
    SIMPLELOG << "Connection removed\n";
    if (was_master) notify_all();
  }

  void process_packet_out(Connection *connection,
                          const p4::PacketOut &packet_out) const {
    std::lock_guard<std::mutex> lock(m);
    SIMPLELOG << "PACKET OUT\n";
    if (!is_master(connection)) return;
    if (device_mgr == nullptr) return;
    device_mgr->packet_out_send(packet_out);
  }

  bool is_master(const Uint128 &election_id) const {
    std::lock_guard<std::mutex> lock(m);
    auto master = get_master();
    return (master == nullptr) ? false : (master->election_id() == election_id);
  }

  size_t connections_size() const {
    std::lock_guard<std::mutex> lock(m);
    return connections.size();
  }

 private:
  Connection *get_master() const {
    return connections.empty() ? nullptr : *connections.begin();
  }

  bool is_master(const Connection *connection) const {
    return connection == get_master();
  }

  void notify_one(const Connection *connection) const {
    auto is_master = (connection == *connections.begin());
    auto stream = connection->stream();
    p4::StreamMessageResponse response;
    auto arbitration = response.mutable_arbitration();
    arbitration->set_device_id(device_id);
    auto convert_u128 = [](const Uint128 &from, p4::Uint128 *to) {
      to->set_high(from.high());
      to->set_low(from.low());
    };
    convert_u128(connection->election_id(), arbitration->mutable_election_id());
    auto status = arbitration->mutable_status();
    if (is_master) {
      status->set_code(::google::rpc::Code::OK);
      status->set_message("Is master");
    } else {
      status->set_code(::google::rpc::Code::ALREADY_EXISTS);
      status->set_message("Is slave");
    }
    stream->Write(response);
  }

  void notify_all() const {
    for (auto connection : connections) notify_one(connection);
  }

  mutable std::mutex m{};
  std::unique_ptr<DeviceMgr> device_mgr{nullptr};
  std::set<Connection *, CompareConnections> connections{};
  DeviceMgr::device_id_t device_id;
};

class Devices {
 public:
  static DeviceState *get(DeviceMgr::device_id_t device_id) {
    auto &instance = get_instance();
    std::lock_guard<std::mutex> lock(instance.m);
    auto &map = instance.device_map;
    auto it = map.find(device_id);
    if (it != map.end()) return it->second.get();
    auto device = new DeviceState(device_id);
    map.emplace(device_id, std::unique_ptr<DeviceState>(device));
    return device;
  }

 private:
  static Devices &get_instance() {
    static Devices devices;
    return devices;
  }

  mutable std::mutex m{};
  std::unordered_map<DeviceMgr::device_id_t,
                     std::unique_ptr<DeviceState> > device_map{};
};

class gNMIServiceImpl : public gnmi::gNMI::Service {
 private:
  Status Capabilities(ServerContext *context,
                      const gnmi::CapabilityRequest *request,
                      gnmi::CapabilityResponse *response) override {
    (void) request; (void) response;
    SIMPLELOG << "gNMI Capabilities\n";
    SIMPLELOG << request->DebugString();
    return Status(StatusCode::UNIMPLEMENTED, "not implemented yet");
  }

  Status Get(ServerContext *context, const gnmi::GetRequest *request,
             gnmi::GetResponse *response) override {
    SIMPLELOG << "gNMI Get\n";
    SIMPLELOG << request->DebugString();
    auto status = ConfigMgrInstance::get()->get(*request, response);
    return to_grpc_status(status);
  }

  Status Set(ServerContext *context, const gnmi::SetRequest *request,
             gnmi::SetResponse *response) override {
    SIMPLELOG << "gNMI Set\n";
    SIMPLELOG << request->DebugString();
    auto status = ConfigMgrInstance::get()->set(*request, response);
    return to_grpc_status(status);
  }

  Status Subscribe(
      ServerContext *context,
      ServerReaderWriter<gnmi::SubscribeResponse,
                         gnmi::SubscribeRequest> *stream) override {
    SIMPLELOG << "gNMI Subscribe\n";
    gnmi::SubscribeRequest request;
    // keeping the channel open, but not doing anything
    // if we receive a Write, we will return an error status
    while (stream->Read(&request)) {
      return Status(StatusCode::UNIMPLEMENTED, "not implemented yet");
    }
    return Status::OK;
  }
};

void packet_in_cb(DeviceMgr::device_id_t device_id, p4::PacketIn *packet,
                  void *cookie);

class P4RuntimeServiceImpl : public p4::P4Runtime::Service {
 private:
  Status Write(ServerContext *context,
               const p4::WriteRequest *request,
               p4::WriteResponse *rep) override {
    SIMPLELOG << "P4Runtime Write\n";
    SIMPLELOG << request->DebugString();
    (void) rep;
    auto device = Devices::get(request->device_id());
    // TODO(antonin): if there are no connections, we accept all Write requests
    // with no election_id. This is very convenient for debugging, testing and
    // using grpc_cli, but may need to be changed in production.
    auto num_connections = device->connections_size();
    if (num_connections == 0 && request->has_election_id())
      return not_master_status();
    auto election_id = convert_u128(request->election_id());
    if (num_connections > 0 && !device->is_master(election_id))
      return not_master_status();
    auto device_mgr = device->get_p4_mgr();
    if (device_mgr == nullptr) return no_pipeline_config_status();
    auto status = device_mgr->write(*request);
    return to_grpc_status(status);
  }

  Status Read(ServerContext *context,
              const p4::ReadRequest *request,
              ServerWriter<p4::ReadResponse> *writer) override {
    SIMPLELOG << "P4Runtime Read\n";
    SIMPLELOG << request->DebugString();
    p4::ReadResponse response;
    auto device_mgr = Devices::get(request->device_id())->get_p4_mgr();
    if (device_mgr == nullptr) return no_pipeline_config_status();
    auto status = device_mgr->read(*request, &response);
    writer->Write(response);
    return to_grpc_status(status);
  }

  Status SetForwardingPipelineConfig(
      ServerContext *context,
      const p4::SetForwardingPipelineConfigRequest *request,
      p4::SetForwardingPipelineConfigResponse *rep) override {
    SIMPLELOG << "P4Runtime SetForwardingPipelineConfig\n";
    (void) rep;
    for (const auto &config : request->configs()) {
      auto device = Devices::get(config.device_id());
      // TODO(antonin): if there are no connections, we accept all requests with
      // no election_id. This is very convenient for debugging, testing and
      // using grpc_cli, but may need to be changed in production.
      auto num_connections = device->connections_size();
      if (num_connections == 0 && request->has_election_id())
        return not_master_status();
      auto election_id = convert_u128(request->election_id());
      if (num_connections > 0 && !device->is_master(election_id))
        return not_master_status();
      auto device_mgr = device->get_or_add_p4_mgr();
      auto status = device_mgr->pipeline_config_set(request->action(), config);
      device_mgr->packet_in_register_cb(packet_in_cb, NULL);
      // TODO(antonin): multi-device support
      return to_grpc_status(status);
    }
    return Status::OK;
  }

  Status GetForwardingPipelineConfig(
      ServerContext *context,
      const p4::GetForwardingPipelineConfigRequest *request,
      p4::GetForwardingPipelineConfigResponse *rep) override {
    SIMPLELOG << "P4Runtime GetForwardingPipelineConfig\n";
    for (const auto device_id : request->device_ids()) {
      auto device_mgr = Devices::get(device_id)->get_p4_mgr();
      if (device_mgr == nullptr) return no_pipeline_config_status();
      auto status = device_mgr->pipeline_config_get(rep->add_configs());
      // TODO(antonin): multi-device support
      return to_grpc_status(status);
    }
    return Status::OK;
  }

  Status StreamChannel(ServerContext *context,
                       StreamChannelReaderWriter *stream) override {
    struct ConnectionStatus {
      explicit ConnectionStatus(ServerContext *context)
          : context(context)  { }
      ~ConnectionStatus() {
        if (connection != nullptr)
          Devices::get(device_id)->cleanup_connection(connection.get());
      }

      ServerContext *context;
      std::unique_ptr<Connection> connection{nullptr};
      DeviceMgr::device_id_t device_id{0};
    };
    ConnectionStatus connection_status(context);

    p4::StreamMessageRequest request;
    while (stream->Read(&request)) {
      switch (request.update_case()) {
        case p4::StreamMessageRequest::kArbitration:
          {
            auto device_id = request.arbitration().device_id();
            auto election_id = convert_u128(
                request.arbitration().election_id());
            // TODO(antonin): a lot of existing code will break if 0 is not
            // valid anymore
            // if (election_id == 0) {
            //   return Status(StatusCode::INVALID_ARGUMENT,
            //                 "Invalid election id value");
            // }
            auto connection = connection_status.connection.get();
            if (connection != nullptr &&
                connection_status.device_id != device_id) {
              return Status(StatusCode::FAILED_PRECONDITION,
                            "Invalid device id");
            }
            if (connection == nullptr) {
              connection_status.connection = Connection::make(
                  election_id, stream, context);
              auto status = Devices::get(device_id)->add_connection(
                  connection_status.connection.get());
              if (!status.ok()) {
                connection_status.connection.release();
                return status;
              }
              connection_status.device_id = device_id;
            } else {
              auto status = Devices::get(device_id)->update_connection(
                  connection_status.connection.get(), election_id);
              if (!status.ok()) return status;
            }
          }
          break;
        case p4::StreamMessageRequest::kPacket:
          {
            if (connection_status.connection == nullptr) break;
            auto device_id = connection_status.device_id;
            Devices::get(device_id)->process_packet_out(
                connection_status.connection.get(), request.packet());
          }
          break;
        default:
          break;
      }
    }
    return Status::OK;
  }

  static Uint128 convert_u128(const p4::Uint128 &from) {
    return Uint128(from.high(), from.low());
  }
};

void packet_in_cb(DeviceMgr::device_id_t device_id, p4::PacketIn *packet,
                  void *cookie) {
  (void) cookie;
  SIMPLELOG << "PACKET IN\n";
  Devices::get(device_id)->send_packet_in(packet);
}

struct ServerData {
  std::string server_address;
  P4RuntimeServiceImpl pi_service;
  gNMIServiceImpl gnmi_service;
  ServerBuilder builder;
  std::unique_ptr<Server> server;
};

}  // namespace

namespace testing {

void send_packet_in(DeviceMgr::device_id_t device_id, p4::PacketIn *packet) {
  packet_in_cb(device_id, packet, nullptr);
}

size_t max_connections() { return DeviceState::max_connections; }

}  // namespace testing

}  // namespace server

}  // namespace pi

namespace {

pi::server::ServerData *server_data;

}  // namespace

extern "C" {

void PIGrpcServerRunAddr(const char *server_address) {
  server_data = new ::pi::server::ServerData();
  server_data->server_address = std::string(server_address);
  auto &builder = server_data->builder;
  builder.AddListeningPort(
    server_data->server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&server_data->pi_service);
  builder.RegisterService(&server_data->gnmi_service);
  builder.SetMaxReceiveMessageSize(256*1024*1024);  // 256MB

  server_data->server = builder.BuildAndStart();
  std::cout << "Server listening on " << server_data->server_address << "\n";
}

void PIGrpcServerRun() {
  PIGrpcServerRunAddr("0.0.0.0:50051");
}

void PIGrpcServerWait() {
  server_data->server->Wait();
}

void PIGrpcServerShutdown() {
  server_data->server->Shutdown();
}

void PIGrpcServerForceShutdown(int deadline_seconds) {
  using clock = std::chrono::system_clock;
  auto deadline = clock::now() + std::chrono::seconds(deadline_seconds);
  server_data->server->Shutdown(deadline);
}

void PIGrpcServerCleanup() {
  delete server_data;
}

}
