#include <PI/pi.h>
#include <PI/frontends/cpp/tables.h>

#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include <grpc++/grpc++.h>

#include "pi.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::CompletionQueue;
using grpc::ServerCompletionQueue;

namespace {

void packetin_cb(pi_dev_id_t dev_id, const char *pkt, size_t size,
                 void *cookie);

}  // namespace

class PacketInClientMgr;

// Logic and data behind the server's behavior.
class PIServiceImpl : public pirpc::PI::Service {
 public:
  void set_packetin_client_mgr(PacketInClientMgr *mgr) {
    mgr_ = mgr;
  }

 private:
  Status Init(ServerContext *context,
              const pirpc::InitRequest *request,
              pirpc::Status *rep) override {
    std::cout << "PI Init\n";
    pi_status_t status = pi_init(request->num_devices(), NULL);
    if (mgr_) {
      pi_packetin_register_default_cb(::packetin_cb,
                                      static_cast<void *>(mgr_));
    }
    rep->set_status(status);
    return Status::OK;
  }

  Status DeviceAssign(ServerContext *context,
                      const pirpc::DeviceAssignRequest *request,
                      pirpc::Status *rep) override {
    std::cout << "PI DeviceAssign\n";
    pi_status_t status;
    std::vector<pi_assign_extra_t> assign_options;
    for (const auto &p : request->extras()) {
      pi_assign_extra_t e;
      e.key = p.first.c_str();
      e.v = p.second.c_str();
      e.end_of_extras = 0;
      assign_options.push_back(e);
    }
    assign_options.push_back({1, NULL, NULL});
    pi_p4info_t *p4info;
    // TODO(antonin): destroy?
    status = pi_add_config(request->native_p4info_json().c_str(),
                           PI_CONFIG_TYPE_NATIVE_JSON, &p4info);
    if (status != PI_STATUS_SUCCESS) {
      rep->set_status(status);
      return Status::OK;
    }
    status = pi_assign_device(request->device_id(), p4info,
                              assign_options.data());
    rep->set_status(status);
    return Status::OK;
  }

  Status DeviceRemove(ServerContext *context,
                      const pirpc::DeviceRemoveRequest *request,
                      pirpc::Status *rep) override {
    std::cout << "PI DeviceRemove\n";
    pi_status_t status = pi_remove_device(request->device_id());
    rep->set_status(status);
    return Status::OK;
  }

  Status DeviceUpdateStart(ServerContext *context,
                           const pirpc::DeviceUpdateStartRequest *request,
                           pirpc::Status *rep) override {
    std::cout << "PI DeviceUpdateStart\n";
    pi_status_t status;
    pi_p4info_t *p4info;
    // TODO(antonin): destroy?
    status = pi_add_config(request->native_p4info_json().c_str(),
                           PI_CONFIG_TYPE_NATIVE_JSON, &p4info);
    if (status != PI_STATUS_SUCCESS) {
      rep->set_status(status);
      return Status::OK;
    }
    status = pi_update_device_start(request->device_id(), p4info,
                                    request->device_data().data(),
                                    request->device_data().size());
    rep->set_status(status);
    return Status::OK;
  }

  Status DeviceUpdateEnd(ServerContext *context,
                         const pirpc::DeviceUpdateEndRequest *request,
                         pirpc::Status *rep) override {
    std::cout << "PI DeviceUpdateEnd\n";
    pi_status_t status = pi_update_device_end(request->device_id());
    rep->set_status(status);
    return Status::OK;
  }

  Status PacketOutSend(ServerContext *context,
                       const pirpc::PacketOut *request,
                       pirpc::Status *rep) override {
    std::cout << "PI PacketOutSend\n";
    pi_status_t status = pi_packetout_send(request->device_id(),
                                           request->packet_data().data(),
                                           request->packet_data().size());
    rep->set_status(status);
    return Status::OK;
  }

  Status TableAdd(ServerContext *context,
                  const pirpc::TableAddRequest *request,
                  pirpc::TableAddResponse *rep) override {
    std::cout << "PI TableAdd\n";
    pi_dev_id_t dev_id = request->device_id();
    const pi_p4info_t *p4info = pi_get_device_p4info(dev_id);
    assert(p4info);
    pi_dev_tgt_t dev_tgt = {dev_id, 0xff};
    pi_p4_id_t t_id = request->table_id();
    const auto &match_action_entry = request->entry();

    // match key
    pi::MatchKey match_key(p4info, t_id);
    for (const auto &mf : match_action_entry.match_key()) {
      switch (mf.match_type()) {
        case pirpc::TableMatchEntry_MatchField_MatchType_EXACT:
          match_key.set_exact(mf.field_id(), mf.exact().value().data(),
                              mf.exact().value().size());
          break;
        case pirpc::TableMatchEntry_MatchField_MatchType_LPM:
          match_key.set_lpm(mf.field_id(), mf.lpm().value().data(),
                            mf.lpm().value().size(), mf.lpm().prefix_len());
          break;
        default:
          // TODO(antonin)
          assert(0 && "field match type not implemented");
          break;
      }
    }

    auto action_data = convert_to_action_data(p4info,
                                              match_action_entry.entry());

    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    pi_entry_handle_t handle = 0;
    pi_status_t status = mt.entry_add(match_key, *action_data,
                                      request->overwrite(), &handle);
    rep->mutable_status()->set_status(status);
    rep->set_entry_handle(handle);
    return Status::OK;
  }

  Status TableDelete(ServerContext *context,
                     const pirpc::TableDeleteRequest *request,
                     pirpc::Status *rep) override {
    std::cout << "PI TableDelete\n";
    pi_dev_id_t dev_id = request->device_id();
    const pi_p4info_t *p4info = pi_get_device_p4info(dev_id);
    assert(p4info);
    pi_dev_tgt_t dev_tgt = {dev_id, 0xff};
    pi_p4_id_t t_id = request->table_id();
    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    pi_status_t status = mt.entry_delete(request->entry_handle());
    rep->set_status(status);
    return Status::OK;
  }

  Status TableSetDefault(ServerContext *context,
                         const pirpc::TableSetDefaultRequest *request,
                         pirpc::Status *rep) override {
    std::cout << "PI TableSetDefault\n";
    pi_dev_id_t dev_id = request->device_id();
    const pi_p4info_t *p4info = pi_get_device_p4info(dev_id);
    assert(p4info);
    pi_dev_tgt_t dev_tgt = {dev_id, 0xff};
    pi_p4_id_t t_id = request->table_id();
    auto action_data = convert_to_action_data(p4info, request->entry());
    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    pi_status_t status = mt.default_entry_set(*action_data);
    rep->set_status(status);
    return Status::OK;
  }

  Status CounterRead(ServerContext *context,
                     const pirpc::CounterReadRequest *request,
                     pirpc::CounterReadResponse *rep) override {
    std::cout << "PI CounterRead\n";
    pi_dev_id_t dev_id = request->device_id();
    pi_dev_tgt_t dev_tgt = {dev_id, 0xff};
    pi_p4_id_t counter_id = request->counter_id();
    pi_counter_data_t counter_data;
    int flags = PI_COUNTER_FLAGS_NONE;
    const pi_p4info_t *p4info = pi_get_device_p4info(dev_id);
    assert(p4info);
    bool is_direct =
        (pi_p4info_counter_get_direct(p4info, counter_id) != PI_INVALID_ID);
    auto target = request->target_case();
    pi_status_t status;
    if (is_direct) {
      assert(target == pirpc::CounterReadRequest::kEntryHandle);
      status = pi_counter_read_direct(sess, dev_tgt, counter_id,
                                      request->entry_handle(), flags,
                                      &counter_data);
    } else {
      assert(target == pirpc::CounterReadRequest::kIndex);
      status = pi_counter_read(sess, dev_tgt, counter_id,
                               request->index(), flags, &counter_data);
    }
    rep->mutable_status()->set_status(status);
    if (status == PI_STATUS_SUCCESS) {
      auto data = rep->mutable_data();
      if (counter_data.valid & PI_COUNTER_UNIT_PACKETS)
        data->set_packets(counter_data.packets);
      if (counter_data.valid & PI_COUNTER_UNIT_BYTES)
        data->set_bytes(counter_data.bytes);
    }
    return Status::OK;
  }

  Status CounterWrite(ServerContext *context,
                      const pirpc::CounterWriteRequest *request,
                      pirpc::Status *rep) override {
    std::cout << "PI CounterWrite\n";
    pi_dev_id_t dev_id = request->device_id();
    pi_dev_tgt_t dev_tgt = {dev_id, 0xff};
    pi_p4_id_t counter_id = request->counter_id();
    pi_counter_data_t counter_data;
    // TODO(antonin): add an enum to proto
    counter_data.valid = PI_COUNTER_UNIT_PACKETS & PI_COUNTER_UNIT_BYTES;
    counter_data.packets = request->data().packets();
    counter_data.bytes = request->data().bytes();
    const pi_p4info_t *p4info = pi_get_device_p4info(dev_id);
    assert(p4info);
    bool is_direct =
        (pi_p4info_counter_get_direct(p4info, counter_id) != PI_INVALID_ID);
    auto target = request->target_case();
    pi_status_t status;
    if (is_direct) {
      assert(target == pirpc::CounterWriteRequest::kEntryHandle);
      status = pi_counter_write_direct(sess, dev_tgt, counter_id,
                                       request->entry_handle(), &counter_data);
    } else {
      assert(target == pirpc::CounterWriteRequest::kIndex);
      status = pi_counter_write(sess, dev_tgt, counter_id,
                                request->index(), &counter_data);
    }
    rep->set_status(status);
    return Status::OK;
  }

  // temporary walk-around as pi::ActionData is not copyable
  std::unique_ptr<pi::ActionData> convert_to_action_data(
      const pi_p4info_t *p4info, const pirpc::TableEntry &entry) {
    assert(entry.entry_type() == pirpc::TableEntry_EntryType_DATA);
    const auto &action_entry = entry.action_data();
    pi_p4_id_t a_id = action_entry.action_id();

    std::unique_ptr<pi::ActionData> action_data(
        new pi::ActionData(p4info, a_id));
    for (const auto &arg : action_entry.args()) {
      action_data->set_arg(arg.param_id(), arg.value().data(),
                           arg.value().size());
    }

    return action_data;
  }

  pi_session_handle_t sess{0};
  PacketInClientMgr *mgr_{nullptr};
};


typedef pirpc::PI::WithAsyncMethod_PacketInReceive<PIServiceImpl>
PIHybridService;

class PacketInClientMgr {
 public:
  PacketInClientMgr(PIHybridService *service, ServerCompletionQueue* cq)
      : service_(service), cq_(cq) {
    new PacketInData(this, service, cq);
  }

  class PacketInData {
   public:
    PacketInData(PacketInClientMgr *mgr, PIHybridService *service,
                 ServerCompletionQueue* cq)
        : mgr_(mgr), service_(service), cq_(cq),
          response_writer(&ctx), state(State::CREATE) {
      proceed();
    }

    int send(int dev_id, const char *pkt, size_t size) {
      {
        std::unique_lock<std::mutex> L(m_);
        if (state != State::CAN_WRITE) return 0;
        state = State::MUST_WAIT;
      }
      response.set_device_id(dev_id);
      response.set_packet_data(pkt, size);
      response_writer.Write(response, this);
      return size;
    }

    void proceed(bool ok = true) {
      std::unique_lock<std::mutex> L(m_);
      if (!ok) state = State::FINISH;
      if (state == State::CREATE) {
        // std::cout << "CREATE\n";
        state = State::CAN_WRITE;
        service_->RequestPacketInReceive(&ctx, &request, &response_writer,
                                         cq_, cq_, this);
      } else if (state == State::CAN_WRITE) {
        // std::cout << "WRITE\n";
        new PacketInData(mgr_, service_, cq_);
        mgr_->register_client(this);
      } else if (state == State::MUST_WAIT) {
        // std::cout << "MUST_WAIT\n";
        state = State::CAN_WRITE;
      } else {
        assert(state == State::FINISH);
        mgr_->remove_client(this);
        delete this;
      }
    }

   private:
    PacketInClientMgr *mgr_;
    PIHybridService *service_;
    ServerCompletionQueue* cq_;
    ServerContext ctx{};
    grpc::ServerAsyncWriter<pirpc::PacketIn> response_writer;;
    pirpc::Empty request{};
    pirpc::PacketIn response{};
    mutable std::mutex m_;
    enum class State { CREATE, CAN_WRITE, MUST_WAIT, FINISH };
    State state;  // The current serving state
  };

  void next() {
    void *tag;
    bool ok;
    assert(cq_->Next(&tag, &ok));
    static_cast<PacketInData *>(tag)->proceed(ok);
  }

  void notify_clients(int dev_id, const char *pkt, size_t size) {
    // std::cout << "NOTIFYING\n";
    std::vector<PacketInData *> clients_;
    {
      std::unique_lock<std::mutex> L(mgr_m_);
      clients_ = clients;
    }
    for (auto c : clients_) c->send(dev_id, pkt, size);
  }

 private:
  void register_client(PacketInData *client) {
    std::unique_lock<std::mutex> L(mgr_m_);
    clients.push_back(client);
  }

  void remove_client(PacketInData *client) {
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
  std::vector<PacketInData *> clients;
};

void HandlePacketInReceive(PacketInClientMgr *mgr) {
  while (true) {
    mgr->next();
  }
}

void probe(PacketInClientMgr *mgr) {
  for (int i = 0; i < 100; i++) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::string t("11111");
    mgr->notify_clients(i, t.data(), t.size());
  }
}

namespace {

void packetin_cb(pi_dev_id_t dev_id, const char *pkt, size_t size,
                 void *cookie) {
  PacketInClientMgr *mgr = static_cast<PacketInClientMgr *>(cookie);
  mgr->notify_clients(dev_id, pkt, size);
}

}  // namespace

void RunServer() {
  std::string server_address("0.0.0.0:50051");
  // PIServiceImpl service;
  PIHybridService service;

  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  auto cq_ = builder.AddCompletionQueue();

  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  PacketInClientMgr mgr(&service, cq_.get());
  service.set_packetin_client_mgr(&mgr);

  std::thread packetin_thread(HandlePacketInReceive, &mgr);

  // std::thread test_thread(probe, &mgr);

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char** argv) {
  RunServer();

  return 0;
}
