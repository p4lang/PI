/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
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
 * Antonin Bas
 *
 */

#include <grpcpp/grpcpp.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

#include "p4/v1/p4runtime.grpc.pb.h"

#include "pi_server_testing.h"
#include "uint128.h"

#include "google/rpc/code.pb.h"

#include "mock_switch.h"
#include "utils.h"

namespace p4v1 = ::p4::v1;

namespace pi {
namespace proto {
namespace testing {
namespace {

using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

// TODO(antonin): We use a synchronous client for the sake of simplicity. This
// is not optimal as it doesn't let us set deadlines on read operations, which
// makes it difficult to have a negative test for packet in (for examples).

// TODO(antonin): We do not set the P4 forwarding pipeline, which means that a
// Write operation is considered successful if it returns
// FAILED_PRECONDITION. It also means that we cannot test packet out
// "end-to-end" (packets are dropped if no P4 pipeline at the moment).

class TestArbitration : public ::testing::Test {
 protected:
  TestArbitration()
      : p4runtime_channel(grpc::CreateChannel(
            server->bind_addr(), grpc::InsecureChannelCredentials())),
        p4runtime_stub(p4v1::P4Runtime::NewStub(p4runtime_channel)),
        mock(wrapper.sw()) { }

  static void SetUpTestCase() {
    server = new TestServer();
  }

  static void TearDownTestCase() {
    delete server;
  }

  using ReaderWriter = ::grpc::ClientReaderWriter<p4v1::StreamMessageRequest,
                                                  p4v1::StreamMessageResponse>;

  static ::Uint128 convert_election_id(const p4v1::Uint128 &from) {
    return ::Uint128(from.high(), from.low());
  }

  static void set_election_id(const ::Uint128 &from, p4v1::Uint128 *to) {
    to->set_high(from.high());
    to->set_low(from.low());
  }

  std::unique_ptr<ReaderWriter> stream_setup(ClientContext *context,
                                             const ::Uint128 &election_id) {
    auto stream = p4runtime_stub->StreamChannel(context);
    p4v1::StreamMessageRequest request;
    auto arbitration = request.mutable_arbitration();
    arbitration->set_device_id(device_id);
    set_election_id(election_id, arbitration->mutable_election_id());
    stream->Write(request);
    return stream;
  }

  Status stream_teardown(std::unique_ptr<ReaderWriter> stream) {
    stream->WritesDone();
    p4v1::StreamMessageResponse response;
    while (stream->Read(&response))  // check that no extra messages
      grpc::Status status(StatusCode::UNKNOWN, "");
    return stream->Finish();
  }

  ::google::rpc::Status read_arbitration_status(ReaderWriter *stream) {
    p4v1::StreamMessageResponse response;
    while (stream->Read(&response)) {
      if (response.update_case() != p4v1::StreamMessageResponse::kArbitration)
        break;
      return response.arbitration().status();
    }
    ::google::rpc::Status status;
    status.set_code(::google::rpc::Code::UNKNOWN);
    return status;
  }

  bool read_packet_in(ReaderWriter *stream) {
    p4v1::StreamMessageResponse response;
    while (stream->Read(&response)) {
      if (response.update_case() != p4v1::StreamMessageResponse::kPacket)
        break;
      return true;
    }
    return false;
  }

  Status do_write(const Uint128 &election_id) {
    p4v1::WriteRequest request;
    request.set_device_id(device_id);
    set_election_id(election_id, request.mutable_election_id());
    ClientContext context;
    p4v1::WriteResponse rep;
    return p4runtime_stub->Write(&context, request, &rep);
  }

  void send_packet_out(ReaderWriter *stream, const std::string &payload) {
    p4v1::StreamMessageRequest request;
    auto packet = request.mutable_packet();
    packet->set_payload(payload);
    stream->Write(request);
  }

  int device_id{0};
  std::shared_ptr<grpc::Channel> p4runtime_channel;
  std::unique_ptr<p4v1::P4Runtime::Stub> p4runtime_stub;
  DummySwitchWrapper wrapper{};
  DummySwitchMock *mock;

  static TestServer *server;
};

TestServer *TestArbitration::server = nullptr;

TEST_F(TestArbitration, WriteNoPrimary) {
  // no streams, empty election id, should go through
  {
    p4v1::WriteRequest request;
    request.set_device_id(device_id);
    ClientContext context;
    p4v1::WriteResponse rep;
    auto status = p4runtime_stub->Write(&context, request, &rep);
    // expect FAILED_PRECONDITION (and not PERMISSION_DENIED)
    EXPECT_EQ(StatusCode::FAILED_PRECONDITION, status.error_code());
  }
  {
    auto status = do_write(1);
    EXPECT_EQ(StatusCode::PERMISSION_DENIED, status.error_code());
  }
}

TEST_F(TestArbitration, DuplicateElectionId) {
  Uint128 election_id(1);
  ClientContext stream_1_context;
  auto stream_1 = stream_setup(&stream_1_context, election_id);
  ASSERT_NE(stream_1, nullptr);
  EXPECT_EQ(read_arbitration_status(stream_1.get()).code(),
            ::google::rpc::Code::OK);
  ClientContext stream_2_context;
  auto stream_2 = stream_setup(&stream_2_context, election_id);
  ASSERT_NE(stream_2, nullptr);
  // need to close stream_2 before stream_1, otherwise the test may fail as
  // stream_1 can end up being closed before the arbitration message for
  // stream_2 has had a chance to be processed by the server
  EXPECT_EQ(stream_teardown(std::move(stream_2)).error_code(),
            StatusCode::INVALID_ARGUMENT);
  EXPECT_TRUE(stream_teardown(std::move(stream_1)).ok());
}

TEST_F(TestArbitration, WriteAndPacketInAndPacketOut) {
  Uint128 primary_id(2);
  Uint128 backup_id(1);
  const std::string payload("aaaa");

  auto check_write = [this](const Uint128 &election_id, bool success) {
    auto status = do_write(election_id);
    if (success)
      EXPECT_EQ(StatusCode::FAILED_PRECONDITION, status.error_code());
    else
      EXPECT_EQ(StatusCode::PERMISSION_DENIED, status.error_code());
  };

  auto check_packet_in = [this, &payload](ReaderWriter *stream) {
    p4v1::PacketIn packet;
    packet.set_payload(payload);
    ::pi::server::testing::send_packet_in(device_id, &packet);
    EXPECT_TRUE(read_packet_in(stream));
  };

  auto check_packet_out = [this, &payload](ReaderWriter *stream) {
    using ::testing::StrEq;
    send_packet_out(stream, payload);
    // TODO(antonin): set a P4 pipeline so we can check this
    // EXPECT_CALL(*mock,
    //             packetout_send(StrEq(payload.c_str()), payload.size()));
  };

  ClientContext stream_primary_context;
  auto stream_primary = stream_setup(&stream_primary_context, primary_id);
  ASSERT_NE(stream_primary, nullptr);

  EXPECT_EQ(read_arbitration_status(stream_primary.get()).code(),
            ::google::rpc::Code::OK);
  EXPECT_EQ(PIGrpcServerGetPacketInCount(device_id), 0u);
  EXPECT_EQ(PIGrpcServerGetPacketOutCount(device_id), 0u);
  check_write(primary_id, true);
  check_packet_in(stream_primary.get());
  check_packet_out(stream_primary.get());
  EXPECT_EQ(PIGrpcServerGetPacketInCount(device_id), 1u);

  ClientContext stream_backup_context;
  auto stream_backup = stream_setup(&stream_backup_context, backup_id);
  ASSERT_NE(stream_backup, nullptr);

  EXPECT_EQ(read_arbitration_status(stream_backup.get()).code(),
            ::google::rpc::Code::ALREADY_EXISTS);
  check_write(primary_id, true);
  check_write(backup_id, false);
  check_packet_in(stream_primary.get());
  check_packet_out(stream_primary.get());
  EXPECT_EQ(PIGrpcServerGetPacketInCount(device_id), 2u);

  EXPECT_TRUE(stream_teardown(std::move(stream_primary)).ok());

  EXPECT_EQ(read_arbitration_status(stream_backup.get()).code(),
            ::google::rpc::Code::OK);
  check_write(backup_id, true);
  check_packet_in(stream_backup.get());
  check_packet_out(stream_backup.get());
  EXPECT_EQ(PIGrpcServerGetPacketInCount(device_id), 3u);

  EXPECT_TRUE(stream_teardown(std::move(stream_backup)).ok());
}

TEST_F(TestArbitration, MaxConnections) {
  const auto max_connections = ::pi::server::testing::max_connections();
  Uint128 election_id(100);
  std::vector<ClientContext> contexts(max_connections);
  std::vector<std::unique_ptr<ReaderWriter> > streams;
  for (size_t i = 0; i < max_connections; i++) {
    auto stream = stream_setup(&contexts.at(i), election_id--);
    if (i == 0) {
      EXPECT_EQ(read_arbitration_status(stream.get()).code(),
                ::google::rpc::Code::OK);
    } else {
      EXPECT_EQ(read_arbitration_status(stream.get()).code(),
                ::google::rpc::Code::ALREADY_EXISTS);
    }
    streams.push_back(std::move(stream));
  }
  {  // cannot add one more connection
    ClientContext context;
    auto extra_stream = stream_setup(&context, election_id--);
    EXPECT_EQ(stream_teardown(std::move(extra_stream)).error_code(),
              StatusCode::RESOURCE_EXHAUSTED);
  }
  for (auto &stream : streams)
    EXPECT_TRUE(stream_teardown(std::move(stream)).ok());
  {  // now we can add one
    ClientContext context;
    auto extra_stream = stream_setup(&context, election_id--);
    EXPECT_EQ(read_arbitration_status(extra_stream.get()).code(),
              ::google::rpc::Code::OK);
    EXPECT_TRUE(stream_teardown(std::move(extra_stream)).ok());
  }
}

// The SingleThreadedClient test was added because of a deadlock in the server
// implementation exposed by using a P4Runtime client reading streamed packet-in
// messages and reacting to them with Write RPCs in the same thread.
// See https://github.com/p4lang/PI/issues/523.
TEST_F(TestArbitration, SingleThreadedClient) {
  Uint128 election_id(1);
  // These need to be large enough to account for buffering at the network
  // interface.
  const std::string payload(1000, 'a');
  const size_t num_packets = 10000;

  ClientContext stream_context;
  auto stream = stream_setup(&stream_context, election_id);
  ASSERT_NE(stream, nullptr);

  EXPECT_EQ(read_arbitration_status(stream.get()).code(),
            ::google::rpc::Code::OK);

  auto send_packet_ins = [this, &payload]() {
    for (size_t i = 0; i < num_packets; i++) {
      p4v1::PacketIn packet;
      packet.set_payload(payload);
      ::pi::server::testing::send_packet_in(device_id, &packet);
    }
  };

  auto handle_packet_ins = [this, &election_id, &stream]() {
    for (size_t i = 0; i < num_packets; i++) {
      EXPECT_TRUE(read_packet_in(stream.get()));
      auto status = do_write(election_id);
      EXPECT_EQ(StatusCode::FAILED_PRECONDITION, status.error_code());
    }
  };

  std::thread thread1(handle_packet_ins);
  std::thread thread2(send_packet_ins);
  thread1.join();
  thread2.join();

  EXPECT_TRUE(stream_teardown(std::move(stream)).ok());
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
