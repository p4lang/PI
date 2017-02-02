#include <PI/frontends/proto/device_mgr.h>

#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <atomic>

#include <csignal>

#include <grpc++/grpc++.h>

#include "p4/p4runtime.grpc.pb.h"
#include "p4/tmp/device.grpc.pb.h"
#include "google/rpc/code.pb.h"

#include "pi_server.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerWriter;
using grpc::ServerReaderWriter;
using grpc::Status;
using grpc::CompletionQueue;
using grpc::ServerCompletionQueue;
using grpc::ServerAsyncReaderWriter;

using pi::fe::proto::DeviceMgr;

// #define DEBUG

#ifdef DEBUG
#define ENABLE_SIMPLELOG true
#else
#define ENABLE_SIMPLELOG false
#endif

#define SIMPLELOG if (ENABLE_SIMPLELOG) std::cout

namespace {

class StreamChannelClientMgr;

DeviceMgr *device_mgr = nullptr;

StreamChannelClientMgr *packet_in_mgr;

void packet_in_cb(DeviceMgr::device_id_t device_id, std::string packet,
                  void *cookie);

class DeviceService : public p4::tmp::Device::Service {
 private:
  Status DeviceAssign(ServerContext *context,
                      const p4::tmp::DeviceAssignRequest *request,
                      ::google::rpc::Status *rep) override {
    SIMPLELOG << "P4Runtime DeviceAssign\n";
    SIMPLELOG << request->DebugString();
    device_mgr = new DeviceMgr(request->device_id());
    *rep = device_mgr->init(request->p4info(), request->extras());
    device_mgr->packet_in_register_cb(::packet_in_cb,
                                      static_cast<void *>(packet_in_mgr));
    return Status::OK;
  }

  Status DeviceRemove(ServerContext *context,
                      const p4::tmp::DeviceRemoveRequest *request,
                      ::google::rpc::Status *rep) override {
    SIMPLELOG << "P4Runtime DeviceRemove\n";
    SIMPLELOG << request->DebugString();
    delete device_mgr;
    *rep = ::google::rpc::Status();
    return Status::OK;
  }

  Status DeviceUpdateStart(ServerContext *context,
                           const p4::tmp::DeviceUpdateStartRequest *request,
                           ::google::rpc::Status *rep) override {
    SIMPLELOG << "P4Runtime DeviceUpdateStart\n";
    SIMPLELOG << request->DebugString();
    *rep = device_mgr->update_start(request->p4info(), request->device_data());
    return Status::OK;
  }

  Status DeviceUpdateEnd(ServerContext *context,
                         const p4::tmp::DeviceUpdateEndRequest *request,
                         ::google::rpc::Status *rep) override {
    SIMPLELOG << "P4Runtime DeviceUpdateEnd\n";
    SIMPLELOG << request->DebugString();
    *rep = device_mgr->update_end();
    return Status::OK;
  }
};

class P4RuntimeServiceImpl : public p4::P4Runtime::Service {
 private:
  Status TableWrite(ServerContext *context,
                    const p4::TableWriteRequest *request,
                    p4::TableWriteResponse *rep) override {
    SIMPLELOG << "P4Runtime TableWrite\n";
    SIMPLELOG << request->DebugString();
    bool has_error = false;
    for (const auto &table_update : request->updates()) {
      auto status = device_mgr->table_write(table_update);
      *rep->add_errors() = status;
      if (status.code() != ::google::rpc::Code::OK) has_error = true;
    }
    if (!has_error) rep->clear_errors();
    return Status::OK;
  }

  // TODO(antonin)
  Status TableRead(ServerContext *context,
                   const p4::TableReadRequest *request,
                   ServerWriter<p4::TableReadResponse> *writer) override {
    SIMPLELOG << "P4Runtime TableRead\n";
    SIMPLELOG << request->DebugString();
    (void) context; (void) request; (void) writer;
    return Status::CANCELLED;
  }

  Status ActionProfileWrite(ServerContext *context,
                            const p4::ActionProfileWriteRequest *request,
                            p4::ActionProfileWriteResponse *rep) override {
    SIMPLELOG << "P4Runtime ActionProfileWrite\n";
    SIMPLELOG << request->DebugString();
    bool has_error = false;
    for (const auto &act_prof_update : request->updates()) {
      auto status = device_mgr->action_profile_write(act_prof_update);
      *rep->add_errors() = status;
      if (status.code() != ::google::rpc::Code::OK) has_error = true;
    }
    if (!has_error) rep->clear_errors();
    return Status::OK;
  }

  // TODO(antonin)
  Status ActionProfileRead(
      ServerContext* context,
      const p4::ActionProfileReadRequest* request,
      ServerWriter<p4::ActionProfileReadResponse> *writer) override {
    SIMPLELOG << "P4Runtime ActionProfileRead\n";
    SIMPLELOG << request->DebugString();
    (void) context; (void) request; (void) writer;
    return Status::CANCELLED;
  }

  Status CounterRead(ServerContext *context,
                     const p4::CounterReadRequest *request,
                     ServerWriter<p4::CounterReadResponse> *writer) override {
    SIMPLELOG << "P4Runtime CounterRead\n";
    SIMPLELOG << request->DebugString();
    if (request->counters().empty()) {
      // read all counters
      for (auto it = device_mgr->counter_read_begin();
           it != device_mgr->counter_read_end();
           it++) {
        p4::CounterReadResponse response;
        response.set_complete(it == device_mgr->counter_read_end());
        auto entry = &(*it);
        response.set_allocated_counter_entry(entry);
        writer->Write(response);
        response.release_counter_entry();
      }
    } else {
      const auto &counters = request->counters();
      for (auto it = counters.begin(); it != counters.end(); it++) {
        p4::CounterReadResponse response;
        response.set_complete(it == counters.end());
        auto entry = response.mutable_counter_entry();
        entry->CopyFrom(*it);  // copy CounterEntry from request
        device_mgr->counter_read(entry);
        writer->Write(response);
      }
    }
    return Status::OK;
  }

  // TODO(antonin)
  Status CounterWrite(ServerContext *context,
                      const p4::CounterWriteRequest *request,
                      ServerWriter<p4::CounterWriteResponse> *writer) override {
    SIMPLELOG << "P4Runtime CounterWrite\n";
    // SIMPLELOG << request->DebugString();
    (void) context; (void) request; (void) writer;
    return Status::CANCELLED;
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
            device_mgr->packet_out_send(request.packet().payload());
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

    void send(DeviceMgr::device_id_t device_id, std::string bytes) {
      {
        std::unique_lock<std::mutex> L(m_);
        if (state != State::CAN_WRITE) return;
        state = State::MUST_WAIT;
      }
      auto packet = response.mutable_packet();
      packet->set_allocated_payload(&bytes);
      stream.Write(response, this);
      packet->release_payload();
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

  void notify_clients(DeviceMgr::device_id_t device_id, std::string bytes) {
    // SIMPLELOG << "NOTIFYING\n";
    std::vector<StreamChannelWriter *> clients_;
    {
      std::unique_lock<std::mutex> L(mgr_m_);
      clients_ = clients;
    }
    for (auto c : clients_) c->send(device_id, std::move(bytes));
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

void packet_in_cb(DeviceMgr::device_id_t device_id, std::string packet,
                  void *cookie) {
  auto mgr = static_cast<StreamChannelClientMgr *>(cookie);
  mgr->notify_clients(device_id, std::move(packet));
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
        mgr->notify_clients(0, std::string(1000, '1'));
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
  std::string server_address{"0.0.0.0:50051"};
  DeviceService device_service;
  P4RuntimeHybridService pi_service;
  ServerBuilder builder;
  std::unique_ptr<Server> server;
  std::thread packetin_thread;
  std::unique_ptr<ServerCompletionQueue> cq_;
  PacketInGenerator *generator{nullptr};
};

ServerData *server_data;

}  // namespace

extern "C" {

void PIGrpcServerRun() {
  server_data = new ServerData();
  auto &builder = server_data->builder;
  builder.AddListeningPort(
    server_data->server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&server_data->device_service);
  builder.RegisterService(&server_data->pi_service);
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
