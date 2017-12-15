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

#include <memory>
#include <string>

#include "gnmi.h"

using grpc::Server;
using grpc::ServerBuilder;

using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

namespace pi {
namespace proto {
namespace testing {
namespace {

// Cannot use TestServer class from utils because we need to be able to test
// both gNMI services even when sysrepo is present. The default server (started
// by PIGrpcServerRunAddr) will default to sysrepo if it is present.

class GnmiServer {
 public:
  explicit GnmiServer(std::unique_ptr<gnmi::gNMI::Service> gnmi_service)
      : gnmi_service(std::move(gnmi_service)) {
    builder.AddListeningPort(
        bind_any_addr, grpc::InsecureServerCredentials(), &server_port);
    builder.RegisterService(this->gnmi_service.get());
    server = builder.BuildAndStart();
  }

  ~GnmiServer() {
    server->Shutdown();
  }

  std::string bind_addr() const {
    return std::string("0.0.0.0:") + std::to_string(server_port);
  }

 private:
  static constexpr char bind_any_addr[] = "[::]:0";
  std::unique_ptr<gnmi::gNMI::Service> gnmi_service;
  ServerBuilder builder;
  std::unique_ptr<Server> server;
  int server_port;
};

constexpr char GnmiServer::bind_any_addr[];

class TestGNMI : public ::testing::Test {
 protected:
  TestGNMI()
      : gnmi_channel(grpc::CreateChannel(
            server->bind_addr(), grpc::InsecureChannelCredentials())),
        gnmi_stub(gnmi::gNMI::NewStub(gnmi_channel)) { }

  static void setup_server(std::unique_ptr<gnmi::gNMI::Service> gnmi_service) {
    server = new GnmiServer(std::move(gnmi_service));
  }

  static void teardown_server() {
    delete server;
  }

  static GnmiServer *server;

  std::shared_ptr<grpc::Channel> gnmi_channel;
  std::unique_ptr<gnmi::gNMI::Stub> gnmi_stub;
};

GnmiServer *TestGNMI::server = nullptr;

class TestGNMIDummy : public TestGNMI {
 protected:
  static void SetUpTestCase() {
    setup_server(pi::server::make_gnmi_service_dummy());
  }

  static void TearDownTestCase() {
    teardown_server();
  }
};

// check that Subscribe stream stays open, even though nothing is implemented
// yet
TEST_F(TestGNMIDummy, SubscribeStaysOpen) {
  gnmi::SubscribeRequest req;
  gnmi::SubscribeResponse rep;
  ClientContext context;
  auto stream = gnmi_stub->Subscribe(&context);
  EXPECT_TRUE(stream->WritesDone());
  auto status = stream->Finish();
  EXPECT_TRUE(status.ok());
}

TEST_F(TestGNMIDummy, SubscribeErrorOnWrite) {
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

#ifdef WITH_SYSREPO

class TestGNMISysrepo : public TestGNMI {
 protected:
  static void SetUpTestCase() {
    setup_server(pi::server::make_gnmi_service_sysrepo());
  }

  static void TearDownTestCase() {
    teardown_server();
  }
};

TEST_F(TestGNMISysrepo, Dummy) { }

#endif  // WITH_SYSREPO

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
