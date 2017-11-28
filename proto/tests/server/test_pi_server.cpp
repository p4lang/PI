// Copyright (c) 2017, Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <gtest/gtest.h>
#include <PI/proto/pi_server.h>

namespace pi {
namespace proto {
namespace testing {
namespace {

static std::string grpc_server_addr = "0.0.0.0";
static std::string grpc_server_port = "50051";

void StartGrpcServer() {
  PIGrpcServerRunAddr(grpc_server_addr + ":" + grpc_server_port);
}

void ShutdownGrpcServer() {
  PIGrpcServerShutdown();
}

void SetGrpcServerPort(std::string port) {
  grpc_server_port = port;
}

TEST(TestPIGrpcServer, DefaultPort) {
  StartGrpcServer();
  EXPECT_EQ(PIGrpcServerGetPort(), 50051);
  ShutdownGrpcServer();
}

TEST(TestPIGrpcServer, RandomPort) {
  SetGrpcServerPort("0");
  StartGrpcServer();
  EXPECT_NE(PIGrpcServerGetPort(), 0);
  ShutdownGrpcServer();
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
