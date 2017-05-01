#include <PI/pi.h>

#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <chrono>
#include <algorithm>
#include <atomic>

#include <ctype.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <grpc++/grpc++.h>

#include "p4info_to_and_from_proto.h"  // for p4info_serialize_to_proto

#include "p4/p4runtime.grpc.pb.h"

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

class P4RuntimeClient {
 public:
  P4RuntimeClient(std::shared_ptr<Channel> channel)
      : stub_(p4::P4Runtime::NewStub(channel)) { }

  int write(const p4::WriteRequest &request) {
    p4::WriteResponse rep;
    ClientContext context;
    auto status = stub_->Write(&context, request, &rep);
    assert(status.ok());
    return 0;
  }

  int assign_device(int device_id, const pi_p4info_t *p4info) {
    p4::SetForwardingPipelineConfigRequest request;
    request.set_action(
        p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT);
    auto config = request.add_configs();
    auto p4info_proto = pi::p4info::p4info_serialize_to_proto(p4info);
    config->set_allocated_p4info(&p4info_proto);
    p4::SetForwardingPipelineConfigResponse rep;
    ClientContext context;
    auto status = stub_->SetForwardingPipelineConfig(&context, request, &rep);
    config->release_p4info();
    assert(status.ok());
    return 0;
  }

 private:
  std::unique_ptr<p4::P4Runtime::Stub> stub_;
};

namespace {

template <typename T> std::string uint_to_string(T i);

template <>
std::string uint_to_string<uint16_t>(uint16_t i) {
  i = ntohs(i);
  return std::string(reinterpret_cast<char *>(&i), sizeof(i));
};

template <>
std::string uint_to_string<uint32_t>(uint32_t i) {
  i = ntohl(i);
  return std::string(reinterpret_cast<char *>(&i), sizeof(i));
};

}  // namespace

class StreamChannelSync {
 public:
  StreamChannelSync(std::shared_ptr<Channel> channel)
      : stub_(p4::P4Runtime::NewStub(channel)) {
    stream = stub_->StreamChannel(&context);
  }

  template <typename F>
  void recv_packet_in(F f) {
    stop_f = false;
    recv_thread = std::thread([this, &f]() {
        p4::StreamMessageResponse packet_in;
        while (!stop_f && stream->Read(&packet_in)) {
          f();
        }
    });
  }

  void send_init(int device_id) {
    std::cout << "Sending init\n";
    p4::StreamMessageRequest packet_out_init;
    packet_out_init.mutable_arbitration()->set_device_id(device_id);
    stream->Write(packet_out_init);
  }

  void send_packet_out(std::string bytes) {
    std::cout << "Sending packet out\n";
    p4::StreamMessageRequest packet_out;
    packet_out.mutable_packet()->set_payload(std::move(bytes));
    stream->Write(packet_out);
  }

  void stop() {
    if (stop_f) return;
    stop_f = true;
    recv_thread.join();
  }

 private:
  std::atomic<bool> stop_f{false};
  std::unique_ptr<p4::P4Runtime::Stub> stub_;
  std::thread recv_thread;
  ClientContext context;
  std::unique_ptr<ClientReaderWriter<p4::StreamMessageRequest,
                                     p4::StreamMessageResponse> > stream;
};

class Tester {
 public:
  using clock = std::chrono::system_clock;

  struct MeasureTime {
    MeasureTime()
        : start(clock::now()) { }

    template <typename T>
    uint64_t elapsed() {
      auto time_elapsed = clock::now() - start;
      return std::chrono::duration_cast<T>(time_elapsed).count();
    }

   private:
    clock::time_point start;
  };

  Tester(int device_id, const pi_p4info_t *p4info,
         std::shared_ptr<Channel> channel)
      : device_id(device_id), p4info(p4info),
        pi_client(channel),
        packet_recv(channel) { }

  uint64_t run_table_write_test(size_t iterations, size_t batch_size) {
    MeasureTime mt;
    assert(!pi_client.assign_device(0, p4info));
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "ipv4_lpm");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "set_nhop");
    auto add_entries = [this, t_id, a_id, batch_size](size_t iters) {
      using google::protobuf::Arena;
      for (size_t i = 0; i < iters; i++) {
        // when arenas are enabled in p4runtime.proto
        // Arena arena;
        // p4::TableWriteRequest *request =
        //     Arena::CreateMessage<p4::TableWriteRequest>(&arena);
        p4::WriteRequest request;
        request.set_device_id(device_id);
        for (size_t j = 0; j < batch_size; j++) {
          auto update = request.add_updates();
          update->set_type(p4::Update_Type_INSERT);
          auto entity = update->mutable_entity();
          auto table_entry = entity->mutable_table_entry();
          table_entry->set_table_id(t_id);
          auto mf = table_entry->add_match();
          mf->set_field_id(pi_p4info_table_match_field_id_from_name(
              p4info, t_id, "ipv4.dstAddr"));
          auto mf_lpm = mf->mutable_lpm();
          auto nhop = static_cast<uint32_t>(0x0a00000a);
          auto port = static_cast<uint16_t>(99);
          mf_lpm->set_value(uint_to_string(nhop));
          mf_lpm->set_prefix_len(24);
          auto entry = table_entry->mutable_action();
          auto action = entry->mutable_action();
          action->set_action_id(a_id);
          {
            auto param = action->add_params();
            param->set_param_id(
                pi_p4info_action_param_id_from_name(p4info, a_id, "nhop_ipv4"));
            param->set_value(uint_to_string(nhop));
          }
          {
            auto param = action->add_params();
            param->set_param_id(
                pi_p4info_action_param_id_from_name(p4info, a_id, "port"));
            param->set_value(uint_to_string(port));
          }
        }
        // for 1000 routes, this is 61,000 bytes
        // std::cout << request->ByteSize() << "\n";
        assert(!pi_client.write(request));
      }
    };
    std::thread t1(add_entries, iterations);
    // std::thread t2(add_entries, iterations / 2);
    t1.join();
    // t2.join();
    auto us = mt.elapsed<std::chrono::microseconds>();
    std::cout << us << "\n";
    return us;
  }

  template <size_t Runs, typename F, typename... Args>
  uint64_t run(F f, Args &&...args) {
    std::vector<uint64_t> times;
    for (size_t i = 0; i < Runs; i++) {
      times.push_back((this->*f)(std::forward<Args>(args)...));
    }
    std::nth_element(times.begin(), times.begin() + times.size() / 2,
                     times.end());
    return times.at(times.size() / 2);
  }

  uint64_t run_packet_in_test(size_t num_packets) {
    packet_recv.send_init(device_id);
    std::atomic<size_t> received{0};
    clock::time_point start, end;
    auto recv_fn = [&received, &num_packets, &start, &end]() {
      if (received == 0) start = clock::now();
      received++;
      if (received == num_packets) end = clock::now();
    };
    packet_recv.recv_packet_in(recv_fn);
    std::cout << "Waiting for packets\n";
    while (received < num_packets) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "Exiting\n";
    packet_recv.stop();
    auto time_elapsed = end - start;
    return std::chrono::duration_cast<std::chrono::microseconds>(
        time_elapsed).count();;
  }

 private:
  int device_id;
  const pi_p4info_t *p4info;
  P4RuntimeClient pi_client;
  StreamChannelSync packet_recv;
};

int main(int argc, char** argv) {
  if (parse_opts(argc, argv) != 0) return 1;
  auto channel = grpc::CreateChannel(
      "localhost:50051", grpc::InsecureChannelCredentials());

  pi_p4info_t *p4info;
  pi_add_config_from_file(opt_config_path, PI_CONFIG_TYPE_BMV2_JSON, &p4info);
  Tester tester(0, p4info, channel);

  auto x1 = tester.run<5>(&Tester::run_table_write_test, 1000, 1000);
  std::cout << "table_write (1,000 iters, 1,000 batch size): " << x1 << "\n";
  auto x2 = tester.run<5>(&Tester::run_table_write_test, 10000, 100);
  std::cout << "table_write (10,000 iters, 100 batch size): " << x2 << "\n";
  auto x3 = tester.run_packet_in_test(1000000);
  std::cout << "receiving 1,000,000 packet-ins: " << x3 << "\n";

  return 0;
}
