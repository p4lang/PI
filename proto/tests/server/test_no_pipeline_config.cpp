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

#include "p4/v1/p4runtime.grpc.pb.h"

#include "utils.h"

namespace p4v1 = ::p4::v1;

namespace pi {
namespace proto {
namespace testing {
namespace {

using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

class TestNoForwardingPipeline : public ::testing::Test {
 protected:
  TestNoForwardingPipeline()
      : p4runtime_channel(grpc::CreateChannel(
            server->bind_addr(), grpc::InsecureChannelCredentials())),
        p4runtime_stub(p4v1::P4Runtime::NewStub(p4runtime_channel)) { }

  static void SetUpTestCase() {
    server = new TestServer();
  }

  static void TearDownTestCase() {
    delete server;
  }

  void SetUp() override {
    stream = p4runtime_stub->StreamChannel(&stream_context);
    p4v1::StreamMessageRequest request;
    auto arbitration = request.mutable_arbitration();
    arbitration->set_device_id(device_id);
    stream->Write(request);
  }

  void TearDown() override {
    stream->WritesDone();
    p4v1::StreamMessageResponse response;
    while (stream->Read(&response)) { }
    auto status = stream->Finish();
    EXPECT_TRUE(status.ok());
  }

  int device_id{0};
  std::shared_ptr<grpc::Channel> p4runtime_channel;
  std::unique_ptr<p4v1::P4Runtime::Stub> p4runtime_stub;
  using ReaderWriter = ::grpc::ClientReaderWriter<p4v1::StreamMessageRequest,
                                                  p4v1::StreamMessageResponse>;
  ClientContext stream_context;
  std::unique_ptr<ReaderWriter> stream{nullptr};

  static TestServer *server;
};

TestServer *TestNoForwardingPipeline::server = nullptr;

TEST_F(TestNoForwardingPipeline, Write) {
  p4v1::WriteRequest request;
  request.set_device_id(device_id);
  ClientContext context;
  p4v1::WriteResponse rep;
  auto status = p4runtime_stub->Write(&context, request, &rep);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(StatusCode::FAILED_PRECONDITION, status.error_code());
}

TEST_F(TestNoForwardingPipeline, Read) {
  p4v1::ReadRequest request;
  request.set_device_id(device_id);
  ClientContext context;
  p4v1::ReadResponse rep;
  std::unique_ptr<grpc::ClientReader<p4v1::ReadResponse> > reader(
      p4runtime_stub->Read(&context, request));
  reader->Read(&rep);
  auto status = reader->Finish();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(StatusCode::FAILED_PRECONDITION, status.error_code());
}

TEST_F(TestNoForwardingPipeline, GetForwardingPipelineConfig) {
  p4v1::GetForwardingPipelineConfigRequest request;
  request.set_device_id(device_id);
  ClientContext context;
  p4v1::GetForwardingPipelineConfigResponse rep;
  auto status = p4runtime_stub->GetForwardingPipelineConfig(
      &context, request, &rep);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(StatusCode::FAILED_PRECONDITION, status.error_code());
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
