#include <PI/frontends/proto/device_mgr.h>

#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <atomic>

#include <csignal>

#include <grpc++/grpc++.h>

#include "p4/pi.grpc.pb.h"
#include "p4/tmp/device.grpc.pb.h"
#include "google/rpc/code.pb.h"

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

DeviceMgr *device_mgr = nullptr;

class PacketIOClientMgr;
PacketIOClientMgr *packet_in_mgr = nullptr;

// #define DEBUG

#ifdef DEBUG
#define ENABLE_SIMPLELOG true
#else
#define ENABLE_SIMPLELOG false
#endif

#define SIMPLELOG if (ENABLE_SIMPLELOG) std::cout

namespace {

void packet_in_cb(DeviceMgr::device_id_t device_id, std::string packet,
                  void *cookie);

}  // namespace

class DeviceService : public p4::tmp::Device::Service {
 private:
  Status DeviceAssign(ServerContext *context,
                      const p4::tmp::DeviceAssignRequest *request,
                      ::google::rpc::Status *rep) override {
    SIMPLELOG << "PI DeviceAssign\n";
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
    SIMPLELOG << "PI DeviceRemove\n";
    SIMPLELOG << request->DebugString();
    delete device_mgr;
    *rep = ::google::rpc::Status();
    return Status::OK;
  }

  Status DeviceUpdateStart(ServerContext *context,
                           const p4::tmp::DeviceUpdateStartRequest *request,
                           ::google::rpc::Status *rep) override {
    SIMPLELOG << "PI DeviceUpdateStart\n";
    SIMPLELOG << request->DebugString();
    *rep = device_mgr->update_start(request->p4info(), request->device_data());
    return Status::OK;
  }

  Status DeviceUpdateEnd(ServerContext *context,
                         const p4::tmp::DeviceUpdateEndRequest *request,
                         ::google::rpc::Status *rep) override {
    SIMPLELOG << "PI DeviceUpdateEnd\n";
    SIMPLELOG << request->DebugString();
    *rep = device_mgr->update_end();
    return Status::OK;
  }
};

class PIServiceImpl : public p4::PI::Service {
 private:
  Status TableWrite(ServerContext *context,
                    const p4::TableWriteRequest *request,
                    p4::TableWriteResponse *rep) override {
    SIMPLELOG << "PI TableWrite\n";
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
    SIMPLELOG << "PI TableRead\n";
    SIMPLELOG << request->DebugString();
    (void) context; (void) request; (void) writer;
    return Status::CANCELLED;
  }

  // TODO(antonin)
  Status ActionProfileWrite(ServerContext *context,
                            const p4::ActionProfileWriteRequest *request,
                            p4::ActionProfileWriteResponse *response) override {
    SIMPLELOG << "PI ActionProfileWrite\n";
    SIMPLELOG << request->DebugString();
    (void) context; (void) request; (void) response;
    return Status::CANCELLED;
  }

  // TODO(antonin)
  Status ActionProfileRead(
      ServerContext* context,
      const p4::ActionProfileReadRequest* request,
      ServerWriter<p4::ActionProfileReadResponse> *writer) override {
    SIMPLELOG << "PI ActionProfileRead\n";
    SIMPLELOG << request->DebugString();
    (void) context; (void) request; (void) writer;
    return Status::CANCELLED;
  }

  Status CounterRead(ServerContext *context,
                     const p4::CounterReadRequest *request,
                     ServerWriter<p4::CounterReadResponse> *writer) override {
    SIMPLELOG << "PI CounterRead\n";
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
    SIMPLELOG << "PI CounterWrite\n";
    // SIMPLELOG << request->DebugString();
    (void) context; (void) request; (void) writer;
    return Status::CANCELLED;
  }
};

typedef p4::PI::WithAsyncMethod_PacketIO<PIServiceImpl>
PIHybridService;

class PacketIOClientMgr {
 public:
  PacketIOClientMgr(PIHybridService *service, ServerCompletionQueue* cq)
      : service_(service), cq_(cq) {
    new PacketIOWriter(this, service, cq);
  }

  using ReaderWriter =
      ServerAsyncReaderWriter<p4::PacketInUpdate, p4::PacketOutUpdate>;

  class PacketIOTag {
   public:
    virtual ~PacketIOTag() { }
    virtual void proceed(bool ok = true) = 0;
  };

  class PacketIOReader : public PacketIOTag {
   public:
    PacketIOReader(ReaderWriter *stream)
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
          case p4::PacketOutUpdate::kInit:
            device_id = request.init().device_id();
          break;
          case p4::PacketOutUpdate::kPacket:
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
    p4::PacketOutUpdate request{};
    ReaderWriter *stream;
    enum class State {CREATE, PROCESS, FINISH};
    State state;
  };

  class PacketIOWriter : public PacketIOTag {
   public:
    PacketIOWriter(PacketIOClientMgr *mgr, PIHybridService *service,
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
        service_->RequestPacketIO(&ctx, &stream, cq_, cq_, this);
      } else if (state == State::CAN_WRITE) {
        reader = new PacketIOReader(&stream);
        reader->proceed();
        // SIMPLELOG << "WRITE\n";
        new PacketIOWriter(mgr_, service_, cq_);
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
    PacketIOClientMgr *mgr_;
    PIHybridService *service_;
    ServerCompletionQueue* cq_;
    ServerContext ctx{};
    ServerAsyncReaderWriter<p4::PacketInUpdate, p4::PacketOutUpdate> stream;
    PacketIOReader *reader = nullptr;
    p4::PacketInUpdate response{};
    mutable std::mutex m_;
    enum class State { CREATE, CAN_WRITE, MUST_WAIT, FINISH};
    State state;  // The current serving state
  };

  bool next() {
    void *tag;
    bool ok;
    if (!cq_->Next(&tag, &ok)) return false;
    static_cast<PacketIOTag *>(tag)->proceed(ok);
    return true;
  }

  void notify_clients(DeviceMgr::device_id_t device_id, std::string bytes) {
    // SIMPLELOG << "NOTIFYING\n";
    std::vector<PacketIOWriter *> clients_;
    {
      std::unique_lock<std::mutex> L(mgr_m_);
      clients_ = clients;
    }
    for (auto c : clients_) c->send(device_id, std::move(bytes));
  }

 private:
  void register_client(PacketIOWriter *client) {
    std::unique_lock<std::mutex> L(mgr_m_);
    clients.push_back(client);
  }

  void remove_client(PacketIOWriter *client) {
    std::unique_lock<std::mutex> L(mgr_m_);
    for (auto it = clients.begin(); it != clients.end(); it++) {
      if (*it == client) {
        clients.erase(it);
        break;
      }
    }
  }

  mutable std::mutex mgr_m_;
  PIHybridService *service_;
  ServerCompletionQueue* cq_;
  std::vector<PacketIOWriter *> clients;
};

namespace {

void packet_in_cb(DeviceMgr::device_id_t device_id, std::string packet,
                  void *cookie) {
  auto mgr = static_cast<PacketIOClientMgr *>(cookie);
  mgr->notify_clients(device_id, std::move(packet));
}

// void probe(PacketIOClientMgr *mgr) {
//   for (int i = 0; i < 100; i++) {
//     std::this_thread::sleep_for(std::chrono::seconds(1));
//     mgr->notify_clients(i, std::string("11111"));
//   }
// }

}  // namespace

Server *server_ptr = nullptr;

struct PacketInGenerator {
  PacketInGenerator(PacketIOClientMgr *mgr)
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
  PacketIOClientMgr *mgr;
  std::thread sender;
};

PacketInGenerator *generator = nullptr;

void RunServer() {
  std::string server_address("0.0.0.0:50051");
  DeviceService device_service;
  PIHybridService pi_service;

  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&device_service);
  builder.RegisterService(&pi_service);
  auto cq_ = builder.AddCompletionQueue();

  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  server_ptr = server.get();
  std::cout << "Server listening on " << server_address << std::endl;

  packet_in_mgr = new PacketIOClientMgr(&pi_service, cq_.get());

  auto packet_io = [](PacketIOClientMgr *mgr) {
    while (mgr->next()) { }
  };

  std::thread packetin_thread(packet_io, packet_in_mgr);

  auto handler = [](int s) {
    std::cout << "Server shutting down\n";
    server_ptr->Shutdown();
  };

  auto manage_generator = [](int s) {
    if (s == SIGUSR1) {
      std::cout << "Starting generator\n";
      generator = new PacketInGenerator(packet_in_mgr);
      generator->run();
    } else {
      delete generator;
      generator = nullptr;
    }
  };

  // TODO(antonin): use sigaction?
  std::signal(SIGINT, handler);
  std::signal(SIGTERM, handler);
  std::signal(SIGQUIT, handler);
  std::signal(SIGUSR1, manage_generator);
  std::signal(SIGUSR2, manage_generator);

  // std::thread test_thread(probe, packet_in_mgr);

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
  cq_->Shutdown();
  packetin_thread.join();
  if (generator) delete generator;
}

int main(int argc, char** argv) {
  DeviceMgr::init(256);
  RunServer();
  DeviceMgr::destroy();

  return 0;
}
