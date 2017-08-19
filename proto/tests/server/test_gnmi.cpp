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

#include <grpc++/grpc++.h>

#include <gtest/gtest.h>

#include <gnmi/gnmi.grpc.pb.h>

#include <PI/proto/pi_server.h>

namespace pi {
namespace proto {
namespace testing {
namespace {

using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

// TODO(antonin): provide a base class to manage server and expose a C++ API so
// multiple instances of the server can be run in the same process concurrently.
class TestGNMI : public ::testing::Test {
 protected:
  TestGNMI()
      : gnmi_channel(grpc::CreateChannel(
            grpc_server_addr, grpc::InsecureChannelCredentials())),
        gnmi_stub(gnmi::gNMI::NewStub(gnmi_channel)) { }

  static void SetUpTestCase() {
    PIGrpcServerRunAddr(grpc_server_addr);
  }

  static void TearDownTestCase() {
    PIGrpcServerShutdown();
  }

  int device_id{0};
  std::shared_ptr<grpc::Channel> gnmi_channel;
  std::unique_ptr<gnmi::gNMI::Stub> gnmi_stub;

  static constexpr char grpc_server_addr[] = "0.0.0.0:50052";
};

constexpr char TestGNMI::grpc_server_addr[];

// check that Subscribe stream stays open, even though nothing is implemented
// yet
TEST_F(TestGNMI, SubscribeStaysOpen) {
  gnmi::SubscribeRequest req;
  gnmi::SubscribeResponse rep;
  ClientContext context;
  auto stream = gnmi_stub->Subscribe(&context);
  EXPECT_TRUE(stream->WritesDone());
  auto status = stream->Finish();
  EXPECT_TRUE(status.ok());
}

TEST_F(TestGNMI, SubscribeErrorOnWrite) {
  gnmi::SubscribeRequest req;
  gnmi::SubscribeResponse rep;
  ClientContext context;
  auto stream = gnmi_stub->Subscribe(&context);
  EXPECT_TRUE(stream->Write(req));
  EXPECT_TRUE(stream->WritesDone());
  auto status = stream->Finish();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(StatusCode::UNIMPLEMENTED, status.error_code());
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
