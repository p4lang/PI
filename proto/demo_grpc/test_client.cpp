#include <PI/pi.h>

#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <chrono>

#include <ctype.h>
#include <unistd.h>

#include <grpc++/grpc++.h>

#include "p4info_to_and_from_proto.h"  // for p4info_serialize_to_proto

#include "p4/pi.grpc.pb.h"
#include "p4/tmp/device.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::CompletionQueue;
using grpc::ClientAsyncReaderWriter;
using grpc::ClientReaderWriter;

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

class DeviceClient {
 public:
  DeviceClient(std::shared_ptr<Channel> channel)
      : stub_(p4::tmp::Device::NewStub(channel)) {}

  int assign_device(const char *path) {
    p4::tmp::DeviceAssignRequest request;
    request.set_device_id(0);
    pi_p4info_t *p4info;
    pi_add_config_from_file(path, PI_CONFIG_TYPE_BMV2_JSON, &p4info);
    p4infos[0] = p4info;
    auto p4info_proto = pi::p4info::p4info_serialize_to_proto(p4info);
    request.set_allocated_p4info(&p4info_proto);
    auto extras = request.mutable_extras();
    auto kv = extras->mutable_kv();
    (*kv)["port"] = "9090";
    (*kv)["notifications"] = "ipc:///tmp/bmv2-0-notifications.ipc";
    (*kv)["cpu_iface"] = "veth251";

    ::google::rpc::Status rep;
    ClientContext context;
    Status status = stub_->DeviceAssign(&context, request, &rep);
    request.release_p4info();
    assert(status.ok());
    return rep.code();
  }

 private:
  std::unique_ptr<p4::tmp::Device::Stub> stub_;
  std::unordered_map<int, const pi_p4info_t *> p4infos{};
};

class PacketIOSync {
 public:
  PacketIOSync(std::shared_ptr<Channel> channel)
      : stub_(p4::PI::NewStub(channel)) {
    stream = stub_->PacketIO(&context);
  }

  void recv_packet_in() {
    recv_thread = std::thread([this]() {
        p4::PacketInUpdate packet_in;
        while (stream->Read(&packet_in)) {
          std::cout << "Received packet in bro!\n";
        }
    });
  }

  void send_init(int device_id) {
    std::cout << "Sending init\n";
    p4::PacketOutUpdate packet_out_init;
    packet_out_init.mutable_init()->set_device_id(device_id);
    stream->Write(packet_out_init);
  }

  void send_packet_out(std::string bytes) {
    std::cout << "Sending packet out\n";
    p4::PacketOutUpdate packet_out;
    packet_out.mutable_packet()->set_payload(std::move(bytes));
    stream->Write(packet_out);
  }

 private:
  std::unique_ptr<p4::PI::Stub> stub_;
  std::thread recv_thread;
  ClientContext context;
  std::unique_ptr<ClientReaderWriter<p4::PacketOutUpdate, p4::PacketInUpdate> >
  stream;
};

class PIAsyncClient {
 public:
  PIAsyncClient(std::shared_ptr<Channel> channel)
      : stub_(p4::PI::NewStub(channel)) {}

  void sub_packet_in() {
    recv_thread = std::thread(&PIAsyncClient::AsyncRecvPacketIn, this);
  }

 private:
  // struct for keeping state and data information
  class AsyncRecvPacketInState {
   public:
    AsyncRecvPacketInState(p4::PI::Stub *stub_, CompletionQueue *cq)
        : state(State::CREATE) {
      stream = stub_->AsyncPacketIO(&context, cq, static_cast<void *>(this));
      std::thread t(&AsyncRecvPacketInState::send_init, this);
      t.detach();
    }

    void send_init() {
      while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Trying to write\n";
        p4::PacketOutUpdate packet_out_init;
        packet_out_init.mutable_init()->set_device_id(0);
        stream->Write(packet_out_init, (void *)1);
        // std::this_thread::sleep_for(std::chrono::seconds(1000));
      }
    }

    void proceed(bool ok) {
      if (state == State::FINISH) {
        std::cout << "END!!!\n";
        delete this;
        return;
      }

      if (!ok) state = State::FINISH;

      if (state == State::CREATE) {
        std::cout << "First tag\n";
        state = State::PROCESS;
      } else if (state == State::PROCESS) {
        std::cout << "Async Packet in received\n";
        // std::cout << packet_in.device_id() << "\n";
      }

      if (state == State::PROCESS) {
        stream->Read(&packet_in, static_cast<void *>(this));
      } else {
        assert(state == State::FINISH);
        stream->Finish(&status, static_cast<void *>(this));
      }
    }

   private:
    enum class State {CREATE, PROCESS, FINISH};
    State state;

    p4::PacketInUpdate packet_in;
    p4::PacketOutUpdate packet_out;

    Status status;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    std::unique_ptr<
      ClientAsyncReaderWriter<p4::PacketOutUpdate, p4::PacketInUpdate> >stream;
  };

  void AsyncRecvPacketIn() {
    new AsyncRecvPacketInState(stub_.get(), &cq_);

    void* got_tag;
    bool ok = false;

    // Block until the next result is available in the completion queue "cq".
    while (cq_.Next(&got_tag, &ok)) {
      if (got_tag == (void *) 1) {
        std::cout << "GOT my 1 back\n";
        continue;
      }
      // The tag in this example is the memory location of the call object
      auto call = static_cast<AsyncRecvPacketInState *>(got_tag);
      call->proceed(ok);
    }
  }

  std::unique_ptr<p4::PI::Stub> stub_;
  CompletionQueue cq_;
  std::thread recv_thread;
};

int main(int argc, char** argv) {
  if (parse_opts(argc, argv) != 0) return 1;
  int rc;
  auto channel = grpc::CreateChannel(
      "localhost:50051", grpc::InsecureChannelCredentials());
  DeviceClient client(channel);
  rc = client.assign_device(opt_config_path);
  std::cout << "1. Status received: " << rc << std::endl;
  // rc = client.route_add_test();
  // std::cout << "2. Status received: " << rc << std::endl;
  // PIAsyncClient async_client(channel);
  // async_client.sub_packet_in();
  PacketIOSync packet_io_client(channel);
  packet_io_client.send_init(0);
  std::thread t([&packet_io_client]() {
      while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        packet_io_client.send_packet_out(std::string("33333"));
      }
  });
  packet_io_client.recv_packet_in();

  while (true) std::this_thread::sleep_for(std::chrono::seconds(100));

  return 0;
}
