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

#include <grpc++/grpc++.h>
// #include <grpc++/support/error_details.h>

#include <memory>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>

#include "gnmi.h"
#include "gnmi/gnmi.grpc.pb.h"
#include "google/rpc/code.pb.h"
#include "log.h"
#include "p4/v1/p4runtime.grpc.pb.h"
#include "pi_server_testing.h"
#include "uint128.h"

#include "PI/proto/pi_server.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::ServerReaderWriter;
using grpc::Status;
using grpc::StatusCode;

using pi::fe::proto::DeviceMgr;

namespace p4v1 = ::p4::v1;
namespace p4config = ::p4::config::v1;

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

using StreamChannelReaderWriter = grpc::ServerReaderWriter<
  p4v1::StreamMessageResponse, p4v1::StreamMessageRequest>;

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

  void send_stream_message(p4v1::StreamMessageResponse *msg) {
    std::lock_guard<std::mutex> lock(m);
    auto master = get_master();
    if (master == nullptr) return;
    auto stream = master->stream();
    auto success = stream->Write(*msg);
    if (msg->has_packet() && success) {
      SIMPLELOG << "PACKET IN\n";
      pkt_in_count++;
    }
  }

  uint64_t get_pkt_in_count() {
    std::lock_guard<std::mutex> lock(m);
    return pkt_in_count;
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

  void process_stream_message_request(
      Connection *connection, const p4v1::StreamMessageRequest &request) {
    // these are handled directly by StreamChannel
    assert(request.update_case() != p4v1::StreamMessageRequest::kArbitration);
    std::lock_guard<std::mutex> lock(m);
    if (!is_master(connection)) return;
    if (device_mgr == nullptr) return;
    device_mgr->stream_message_request_handle(request);
    if (request.update_case() == p4v1::StreamMessageRequest::kPacket) {
      SIMPLELOG << "PACKET OUT\n";
      pkt_out_count++;
    }
  }

  uint64_t get_pkt_out_count() {
    std::lock_guard<std::mutex> lock(m);
    return pkt_out_count;
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
    p4v1::StreamMessageResponse response;
    auto arbitration = response.mutable_arbitration();
    arbitration->set_device_id(device_id);
    auto convert_u128 = [](const Uint128 &from, p4v1::Uint128 *to) {
      to->set_high(from.high());
      to->set_low(from.low());
    };
    auto master_connection = get_master();
    convert_u128(master_connection->election_id(),
                 arbitration->mutable_election_id());
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
  uint64_t pkt_in_count{0};
  uint64_t pkt_out_count{0};
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

  static bool has_device(DeviceMgr::device_id_t device_id) {
    auto &instance = get_instance();
    std::lock_guard<std::mutex> lock(instance.m);
    auto &map = instance.device_map;
    return (map.find(device_id) != map.end());
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

void stream_message_response_cb(DeviceMgr::device_id_t device_id,
                                p4v1::StreamMessageResponse *msg,
                                void *cookie);

class P4RuntimeServiceImpl : public p4v1::P4Runtime::Service {
 private:
  Status Write(ServerContext *context,
               const p4v1::WriteRequest *request,
               p4v1::WriteResponse *rep) override {
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
              const p4v1::ReadRequest *request,
              ServerWriter<p4v1::ReadResponse> *writer) override {
    SIMPLELOG << "P4Runtime Read\n";
    SIMPLELOG << request->DebugString();
    p4v1::ReadResponse response;
    auto device_mgr = Devices::get(request->device_id())->get_p4_mgr();
    if (device_mgr == nullptr) return no_pipeline_config_status();
    auto status = device_mgr->read(*request, &response);
    writer->Write(response);
    return to_grpc_status(status);
  }

  Status SetForwardingPipelineConfig(
      ServerContext *context,
      const p4v1::SetForwardingPipelineConfigRequest *request,
      p4v1::SetForwardingPipelineConfigResponse *rep) override {
    SIMPLELOG << "P4Runtime SetForwardingPipelineConfig\n";
    (void) rep;
    auto device = Devices::get(request->device_id());
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
    auto status = device_mgr->pipeline_config_set(
        request->action(), request->config());
    device_mgr->stream_message_response_register_cb(
        stream_message_response_cb, NULL);
    return to_grpc_status(status);
  }

  Status GetForwardingPipelineConfig(
      ServerContext *context,
      const p4v1::GetForwardingPipelineConfigRequest *request,
      p4v1::GetForwardingPipelineConfigResponse *rep) override {
    SIMPLELOG << "P4Runtime GetForwardingPipelineConfig\n";
    auto device_mgr = Devices::get(request->device_id())->get_p4_mgr();
    if (device_mgr == nullptr) return no_pipeline_config_status();
    auto status = device_mgr->pipeline_config_get(
        request->response_type(), rep->mutable_config());
    return to_grpc_status(status);
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

    p4v1::StreamMessageRequest request;
    while (stream->Read(&request)) {
      switch (request.update_case()) {
        case p4v1::StreamMessageRequest::kArbitration:
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
        case p4v1::StreamMessageRequest::kPacket:
        case p4v1::StreamMessageRequest::kDigestAck:
          {
            if (connection_status.connection == nullptr) break;
            auto device_id = connection_status.device_id;
            Devices::get(device_id)->process_stream_message_request(
                connection_status.connection.get(), request);
          }
          break;
        default:
          break;
      }
    }
    return Status::OK;
  }

  static Uint128 convert_u128(const p4v1::Uint128 &from) {
    return Uint128(from.high(), from.low());
  }
};

void stream_message_response_cb(DeviceMgr::device_id_t device_id,
                                p4v1::StreamMessageResponse *msg,
                                void *cookie) {
  (void) cookie;
  Devices::get(device_id)->send_stream_message(msg);
}

struct ServerData {
  std::string server_address;
  int server_port;
  P4RuntimeServiceImpl pi_service;
  std::unique_ptr<gnmi::gNMI::Service> gnmi_service;
  ServerBuilder builder;
  std::unique_ptr<Server> server;
};

}  // namespace

namespace testing {

void send_packet_in(DeviceMgr::device_id_t device_id, p4v1::PacketIn *packet) {
  p4v1::StreamMessageResponse msg;
  msg.set_allocated_packet(packet);
  Devices::get(device_id)->send_stream_message(&msg);
  msg.release_packet();
}

size_t max_connections() { return DeviceState::max_connections; }

}  // namespace testing

}  // namespace server

}  // namespace pi

namespace {

pi::server::ServerData *server_data;

}  // namespace

extern "C" {

void PIGrpcServerRunAddrGnmi(const char *server_address, void *gnmi_service) {
  server_data = new ::pi::server::ServerData();
  server_data->server_address = std::string(server_address);
  auto &builder = server_data->builder;
  builder.AddListeningPort(
    server_data->server_address, grpc::InsecureServerCredentials(),
    &server_data->server_port);
  builder.RegisterService(&server_data->pi_service);
  if (gnmi_service != nullptr) {
    server_data->gnmi_service = std::unique_ptr<gnmi::gNMI::Service>(
            static_cast<gnmi::gNMI::Service *>(gnmi_service));
  } else {
#ifdef WITH_SYSREPO
    server_data->gnmi_service = ::pi::server::make_gnmi_service_sysrepo();
#else
    server_data->gnmi_service = ::pi::server::make_gnmi_service_dummy();
#endif  // WITH_SYSREPO
  }
  builder.RegisterService(server_data->gnmi_service.get());
  builder.SetMaxReceiveMessageSize(256*1024*1024);  // 256MB

  server_data->server = builder.BuildAndStart();
  std::cout << "Server listening on " << server_data->server_address << "\n";
}

void PIGrpcServerRunAddr(const char *server_address) {
  PIGrpcServerRunAddrGnmi(server_address, nullptr);
}

void PIGrpcServerRun() {
  PIGrpcServerRunAddrGnmi("0.0.0.0:50051", nullptr);
}

int PIGrpcServerGetPort() {
  return server_data->server_port;
}

uint64_t PIGrpcServerGetPacketInCount(uint64_t device_id) {
  if (::pi::server::Devices::has_device(device_id)) {
    return ::pi::server::Devices::get(device_id)->get_pkt_in_count();
  }
  return 0;
}

uint64_t PIGrpcServerGetPacketOutCount(uint64_t device_id) {
  if (::pi::server::Devices::has_device(device_id)) {
    return ::pi::server::Devices::get(device_id)->get_pkt_out_count();
  }
  return 0;
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
