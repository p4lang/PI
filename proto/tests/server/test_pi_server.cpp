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
#include <string>

namespace pi {
namespace proto {
namespace testing {
namespace {

const std::string grpc_server_addr = "0.0.0.0";

void StartGrpcServer(int port) {
  std::string bind_addr = grpc_server_addr + ":" + std::to_string(port);
  PIGrpcServerRunAddr(bind_addr.c_str());
}

void ShutdownGrpcServer() {
  PIGrpcServerShutdown();
}

TEST(TestPIGrpcServer, DefaultPort) {
  // maybe we should just get rid of the tests in this file now that we let the
  // OS bind to any port and use PIGrpcServerGetPort() in other tests
  int port = 1024;
  for (; port < 4096; port++) {
    StartGrpcServer(port);
    if (PIGrpcServerGetPort() == port) break;
  }
  ASSERT_EQ(PIGrpcServerGetPort(), port);
  ShutdownGrpcServer();
}

TEST(TestPIGrpcServer, RandomPort) {
  StartGrpcServer(0);
  EXPECT_NE(PIGrpcServerGetPort(), 0);
  ShutdownGrpcServer();
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
