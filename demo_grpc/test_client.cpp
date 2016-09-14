#include <PI/pi.h>

#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <chrono>

#include <ctype.h>
#include <unistd.h>

#include <grpc++/grpc++.h>

#include "pi.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::CompletionQueue;

char *opt_config_path = NULL;

void print_help(const char *name) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]...\n"
          "PI example controller app\n\n"
          "-c          P4 config (json)\n",
          name);
}

int parse_opts(int argc, char *const argv[]) {
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "c:h")) != -1) {
    switch (c) {
      case 'c':
        opt_config_path = optarg;
        break;
      case 'h':
        print_help(argv[0]);
        exit(0);
      case '?':
        if (optopt == 'c') {
          fprintf(stderr, "Option -%c requires an argument.\n\n", optopt);
          print_help(argv[0]);
        } else if (isprint(optopt)) {
          fprintf(stderr, "Unknown option `-%c'.\n\n", optopt);
          print_help(argv[0]);
        } else {
          fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
          print_help(argv[0]);
        }
        return 1;
      default:
        abort();
    }
  }

  if (!opt_config_path) {
    fprintf(stderr, "Options -c is required.\n\n");
    print_help(argv[0]);
    return 1;
  }

  int extra_arg = 0;
  for (int index = optind; index < argc; index++) {
    fprintf(stderr, "Non-option argument: %s\n", argv[index]);
    extra_arg = 1;
  }
  if (extra_arg) {
    print_help(argv[0]);
    return 1;
  }

  return 0;
}

class PIClient {
 public:
  PIClient(std::shared_ptr<Channel> channel)
      : stub_(pirpc::PI::NewStub(channel)) {}

  // Assambles the client's payload, sends it and presents the response back
  // from the server.
  int init(size_t num_devices) {
    // Data we are sending to the server.
    pirpc::InitRequest request;
    request.set_num_devices(num_devices);

    // Container for the data we expect from the server.
    pirpc::Status rep;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // The actual RPC.
    Status status = stub_->Init(&context, request, &rep);

    // Act upon its status.
    if (status.ok()) {
      return rep.status();
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return -1;
    }
  }

  int assign_device(const char *path) {
    pirpc::DeviceAssignRequest request;
    request.set_device_id(0);
    pi_p4info_t *p4info;
    pi_add_config_from_file(path, PI_CONFIG_TYPE_BMV2_JSON, &p4info);
    p4infos[0] = p4info;
    char *p4info_json = pi_serialize_config(p4info, 0);
    request.set_native_p4info_json(std::string(p4info_json));
    (*request.mutable_extras())["port"] = "9090";
    (*request.mutable_extras())["notifications"] =
        "ipc:///tmp/bmv2-0-notifications.ipc";
    (*request.mutable_extras())["cpu_iface"] = "veth251";

    pirpc::Status rep;
    ClientContext context;
    Status status = stub_->DeviceAssign(&context, request, &rep);
    assert(status.ok());
    return rep.status();
  }

  int route_add_test() {
    pirpc::TableAddRequest request;
    request.set_device_id(0);
    const pi_p4info_t *p4info = p4infos[0];
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "ipv4_lpm");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "set_nhop");
    request.set_table_id(t_id);
    request.set_overwrite(true);
    auto match_action_entry = request.mutable_entry();

    auto mf = match_action_entry->add_match_key();
    mf->set_match_type(pirpc::TableMatchEntry_MatchField_MatchType_LPM);
    mf->set_field_id(pi_p4info_field_id_from_name(p4info, "ipv4.dstAddr"));
    auto mf_lpm = mf->mutable_lpm();
    mf_lpm->set_value("\xab\xcd\01\02");
    mf_lpm->set_prefix_len(12);

    auto entry = match_action_entry->mutable_entry();
    entry->set_entry_type(pirpc::TableEntry_EntryType_DATA);
    auto action_entry = entry->mutable_action_data();
    action_entry->set_action_id(a_id);
    {
      auto arg = action_entry->add_args();
      arg->set_param_id(
          pi_p4info_action_param_id_from_name(p4info, a_id, "nhop_ipv4"));
      arg->set_value("\xab\xcd\01\02");
    }
    {
      auto arg = action_entry->add_args();
      arg->set_param_id(
          pi_p4info_action_param_id_from_name(p4info, a_id, "port"));
      arg->set_value(std::string("\x00\x03", 2));
    }

    pirpc::TableAddResponse rep;
    ClientContext context;
    Status status = stub_->TableAdd(&context, request, &rep);
    assert(status.ok());
    std::cout << "h : " << rep.entry_handle() << "\n";
    return rep.status().status();
  }

 private:
  std::unique_ptr<pirpc::PI::Stub> stub_;
  std::unordered_map<int, const pi_p4info_t *> p4infos{};
};

class PIAsyncClient {
 public:
  PIAsyncClient(std::shared_ptr<Channel> channel)
      : stub_(pirpc::PI::NewStub(channel)) {}

  void sub_packet_in() {
    recv_thread = std::thread(&PIAsyncClient::AsyncRecvPacketIn, this);
  }

 private:
  // struct for keeping state and data information
  class AsyncRecvPacketInState {
   public:
    AsyncRecvPacketInState(pirpc::PI::Stub *stub_, CompletionQueue *cq)
        : state(State::CREATE) {
      pirpc::Empty request;
      response_reader = stub_->AsyncPacketInReceive(
          &context, request, cq, static_cast<void *>(this));
    }

    void proceed(bool ok) {
      if (state == State::FINISH) {
        std::cout << "END!!!\n";
        delete this;
        return;
      }

      if (!ok) state = State::FINISH;

      assert(status.ok());

      if (state == State::CREATE) {
        std::cout << "First tag\n";
        state = State::PROCESS;
      } else if (state == State::PROCESS) {
        std::cout << "Async Packet in received\n";
        std::cout << packet_in.device_id() << "\n";
      }

      if (state == State::PROCESS) {
        response_reader->Read(&packet_in, static_cast<void *>(this));
      } else {
        assert(state == State::FINISH);
        response_reader->Finish(&status, static_cast<void *>(this));
      }
    }

   private:
    enum class State {CREATE, PROCESS, FINISH};
    State state;

    // Container for the data we expect from the server.
    pirpc::PacketIn packet_in;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    // Storage for the status of the RPC upon completion.
    Status status;

    std::unique_ptr<grpc::ClientAsyncReader<pirpc::PacketIn> > response_reader;
  };

  void AsyncRecvPacketIn() {
    pirpc::Empty request;
    new AsyncRecvPacketInState(stub_.get(), &cq_);

    void* got_tag;
    bool ok = false;

    // Block until the next result is available in the completion queue "cq".
    while (cq_.Next(&got_tag, &ok)) {
      // The tag in this example is the memory location of the call object
      AsyncRecvPacketInState* call =
          static_cast<AsyncRecvPacketInState *>(got_tag);
      call->proceed(ok);
    }
  }

  std::unique_ptr<pirpc::PI::Stub> stub_;
  CompletionQueue cq_;
  std::thread recv_thread;
};

int main(int argc, char** argv) {
  if (parse_opts(argc, argv) != 0) return 1;
  int rc;
  auto channel = grpc::CreateChannel(
      "localhost:50051", grpc::InsecureChannelCredentials());
  PIClient client(channel);
  rc = client.init(256);
  std::cout << "1. Status received: " << rc << std::endl;
  rc = client.assign_device(opt_config_path);
  std::cout << "2. Status received: " << rc << std::endl;
  rc = client.route_add_test();
  std::cout << "3. Status received: " << rc << std::endl;
  PIAsyncClient async_client(channel);
  async_client.sub_packet_in();

  while (true) std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
