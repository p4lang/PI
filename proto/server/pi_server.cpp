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

#include <PI/frontends/proto/gnmi_mgr.h>
#include <PI/frontends/proto/device_mgr.h>

#include <PI/proto/pi_server.h>

#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <atomic>

#include <csignal>

#include <grpc++/grpc++.h>
// #include <grpc++/support/error_details.h>

#include "gnmi/gnmi.grpc.pb.h"
#include "google/rpc/code.pb.h"
#include "p4/p4runtime.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerWriter;
using grpc::ServerReaderWriter;
using grpc::Status;
using grpc::StatusCode;
using grpc::CompletionQueue;
using grpc::ServerCompletionQueue;
using grpc::ServerAsyncReaderWriter;

using pi::fe::proto::GnmiMgr;
using pi::fe::proto::DeviceMgr;

#define DEBUG

#ifdef DEBUG
#define ENABLE_SIMPLELOG true
#else
#define ENABLE_SIMPLELOG false
#endif

#define SIMPLELOG if (ENABLE_SIMPLELOG) std::cout

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
  auto conversion_status = ::SetErrorDetails(from, &to);
  // This can only fail if the second argument to SetErrorDetails is a nullptr,
  // which cannot be the case here
  assert(conversion_status.ok());
  return to;
}

class ConfigMgrInstance {
 public:
  static GnmiMgr *get() {
    static GnmiMgr mgr;
    return &mgr;
  }
};

DeviceMgr *device_mgr = nullptr;

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
    (void) stream;
    SIMPLELOG << "gNMI Subscribe\n";
    return Status(StatusCode::UNIMPLEMENTED, "not implemented yet");
  }
};

class StreamChannelClientMgr;

StreamChannelClientMgr *packet_in_mgr;

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
    auto status = device_mgr->write(*request);
    return to_grpc_status(status);
  }

  Status Read(ServerContext *context,
              const p4::ReadRequest *request,
              ServerWriter<p4::ReadResponse> *writer) override {
    SIMPLELOG << "P4Runtime Read\n";
    SIMPLELOG << request->DebugString();
    p4::ReadResponse response;
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
      if (device_mgr == nullptr) device_mgr = new DeviceMgr(config.device_id());
      auto status = device_mgr->pipeline_config_set(request->action(), config);
      device_mgr->packet_in_register_cb(::packet_in_cb,
                                        static_cast<void *>(packet_in_mgr));
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
      (void) device_id;
      auto status = device_mgr->pipeline_config_get(rep->add_configs());
      // TODO(antonin): multi-device support
      return to_grpc_status(status);
    }
    return Status::OK;
  }
};

using P4RuntimeHybridService =
  p4::P4Runtime::WithAsyncMethod_StreamChannel<P4RuntimeServiceImpl>;

class StreamChannelClientMgr {
 public:
  StreamChannelClientMgr(P4RuntimeHybridService *service,
                         ServerCompletionQueue* cq)
      : service_(service), cq_(cq) {
    new StreamChannelWriter(this, service, cq);
  }

  using ReaderWriter = ServerAsyncReaderWriter<p4::StreamMessageResponse,
                                               p4::StreamMessageRequest>;

  class StreamChannelTag {
   public:
    virtual ~StreamChannelTag() { }
    virtual void proceed(bool ok = true) = 0;
  };

  class StreamChannelReader : public StreamChannelTag {
   public:
    StreamChannelReader(ReaderWriter *stream)
        : stream(stream), state(State::CREATE) { }

    void proceed(bool ok = true) override {
      if (state == State::FINISH) {
        SIMPLELOG << "END!!!\n";
        delete this;
        return;
      }
      if (!ok) state = State::FINISH;
      if (state == State::CREATE) {
        stream->Read(&request, this);
        state = State::PROCESS;
      } else if (state == State::PROCESS) {
        // SIMPLELOG << "PACKET OUT\n";
        switch (request.update_case()) {
          case p4::StreamMessageRequest::kArbitration:
            device_id = request.arbitration().device_id();
          break;
          case p4::StreamMessageRequest::kPacket:
            device_mgr->packet_out_send(request.packet());
            break;
          default:
            assert(0);
        }
        stream->Read(&request, this);
      } else {
        assert(state == State::FINISH);
        stream->Finish(Status::OK, this);
      }
    }

   private:
    DeviceMgr::device_id_t device_id{};
    p4::StreamMessageRequest request{};
    ReaderWriter *stream;
    enum class State {CREATE, PROCESS, FINISH};
    State state;
  };

  class StreamChannelWriter : public StreamChannelTag {
   public:
    StreamChannelWriter(StreamChannelClientMgr *mgr,
                        P4RuntimeHybridService *service,
                        ServerCompletionQueue* cq)
        : mgr_(mgr), service_(service), cq_(cq),
          stream(&ctx), state(State::CREATE) {
      proceed();
    }

    void send(DeviceMgr::device_id_t device_id, p4::PacketIn *packet) {
      {
        std::unique_lock<std::mutex> L(m_);
        if (state != State::CAN_WRITE) return;
        state = State::MUST_WAIT;
      }
      response.set_allocated_packet(packet);
      stream.Write(response, this);
      response.release_packet();
    }

    void proceed(bool ok = true) override {
      std::unique_lock<std::mutex> L(m_);
      if (!ok) state = State::FINISH;
      if (state == State::CREATE) {
        // SIMPLELOG << "CREATE\n";
        state = State::CAN_WRITE;
        service_->RequestStreamChannel(&ctx, &stream, cq_, cq_, this);
      } else if (state == State::CAN_WRITE) {
        reader = new StreamChannelReader(&stream);
        reader->proceed();
        // SIMPLELOG << "WRITE\n";
        new StreamChannelWriter(mgr_, service_, cq_);
        mgr_->register_client(this);
      } else if (state == State::MUST_WAIT) {
        // SIMPLELOG << "MUST_WAIT\n";
        state = State::CAN_WRITE;
      } else {
        assert(state == State::FINISH);
        mgr_->remove_client(this);
        delete this;
      }
    }

   private:
    StreamChannelClientMgr *mgr_;
    P4RuntimeHybridService *service_;
    ServerCompletionQueue* cq_;
    ServerContext ctx{};
    ServerAsyncReaderWriter<p4::StreamMessageResponse,
                            p4::StreamMessageRequest> stream;
    StreamChannelReader *reader = nullptr;
    p4::StreamMessageResponse response{};
    mutable std::mutex m_;
    enum class State { CREATE, CAN_WRITE, MUST_WAIT, FINISH};
    State state;  // The current serving state
  };

  bool next() {
    void *tag;
    bool ok;
    if (!cq_->Next(&tag, &ok)) return false;
    static_cast<StreamChannelTag *>(tag)->proceed(ok);
    return true;
  }

  void notify_clients(DeviceMgr::device_id_t device_id, p4::PacketIn *packet) {
    // SIMPLELOG << "NOTIFYING\n";
    std::vector<StreamChannelWriter *> clients_;
    {
      std::unique_lock<std::mutex> L(mgr_m_);
      clients_ = clients;
    }
    for (auto c : clients_) c->send(device_id, packet);
  }

 private:
  void register_client(StreamChannelWriter *client) {
    std::unique_lock<std::mutex> L(mgr_m_);
    clients.push_back(client);
  }

  void remove_client(StreamChannelWriter *client) {
    std::unique_lock<std::mutex> L(mgr_m_);
    for (auto it = clients.begin(); it != clients.end(); it++) {
      if (*it == client) {
        clients.erase(it);
        break;
      }
    }
  }

  mutable std::mutex mgr_m_;
#ifdef __clang__
  __attribute__((unused))
#endif
  P4RuntimeHybridService *service_;
  ServerCompletionQueue* cq_;
  std::vector<StreamChannelWriter *> clients;
};

void packet_in_cb(DeviceMgr::device_id_t device_id, p4::PacketIn *packet,
                  void *cookie) {
  auto mgr = static_cast<StreamChannelClientMgr *>(cookie);
  mgr->notify_clients(device_id, packet);
}

// void probe(StreamChannelClientMgr *mgr) {
//   for (int i = 0; i < 100; i++) {
//     std::this_thread::sleep_for(std::chrono::seconds(1));
//     mgr->notify_clients(i, std::string("11111"));
//   }
// }

struct PacketInGenerator {
  PacketInGenerator(StreamChannelClientMgr *mgr)
      : mgr(mgr) { }

  ~PacketInGenerator() { stop(); }

  void run() {
    stop_f = 0;
    sender = std::thread([this]() {
      while (!stop_f) {
        // sending 1000 bytes packets
        p4::PacketIn packet;
        packet.set_payload(std::string(1000, '1'));
        mgr->notify_clients(0, &packet);
      }
    });
  }

  void stop() {
    if (stop_f) return;
    stop_f = 1;
    sender.join();
  }

  std::atomic<int> stop_f{0};
  StreamChannelClientMgr *mgr;
  std::thread sender;
};

struct ServerData {
  std::string server_address;
  P4RuntimeHybridService pi_service;
  gNMIServiceImpl gnmi_service;
  ServerBuilder builder;
  std::unique_ptr<Server> server;
  std::thread packetin_thread;
  std::unique_ptr<ServerCompletionQueue> cq_;
  PacketInGenerator *generator{nullptr};
};

ServerData *server_data;

}  // namespace

extern "C" {

void PIGrpcServerRunAddr(const char *server_address) {
  server_data = new ServerData();
  server_data->server_address = std::string(server_address);
  auto &builder = server_data->builder;
  builder.AddListeningPort(
    server_data->server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&server_data->pi_service);
  builder.RegisterService(&server_data->gnmi_service);
  server_data->cq_ = builder.AddCompletionQueue();

  server_data->server = builder.BuildAndStart();
  std::cout << "Server listening on " << server_data->server_address << "\n";

  packet_in_mgr = new StreamChannelClientMgr(
    &server_data->pi_service, server_data->cq_.get());

  auto packet_io = [](StreamChannelClientMgr *mgr) {
    while (mgr->next()) { }
  };

  server_data->packetin_thread = std::thread(packet_io, packet_in_mgr);

  // for testing only
  auto manage_generator = [](int s) {
    if (s == SIGUSR1) {
      std::cout << "Starting generator\n";
      server_data->generator = new PacketInGenerator(packet_in_mgr);
      server_data->generator->run();
    } else {
      std::cout << "Stopping generator\n";
      delete server_data->generator;
      server_data->generator = nullptr;
    }
  };
  // TODO(antonin): use sigaction?
  std::signal(SIGUSR1, manage_generator);
  std::signal(SIGUSR2, manage_generator);

  // std::thread test_thread(probe, packet_in_mgr);
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

void PIGrpcServerCleanup() {
  server_data->cq_->Shutdown();
  server_data->packetin_thread.join();
  if (server_data->generator) delete server_data->generator;
  delete server_data;
}

}
