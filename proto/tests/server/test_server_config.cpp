// Copyright 2019 VMware, Inc.
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

#include <grpcpp/grpcpp.h>

#include <gtest/gtest.h>

#include "p4/server/v1/config.grpc.pb.h"

#include "matchers.h"
#include "utils.h"

namespace p4serverv1 = ::p4::server::v1;

namespace pi {
namespace proto {
namespace testing {

using grpc::ClientContext;

TEST(TestServerConfig, GetAndSet) {
  int device_id{1};
  TestServer server;

  auto channel = grpc::CreateChannel(
      server.bind_addr(), grpc::InsecureChannelCredentials());
  auto stub = p4serverv1::ServerConfig::NewStub(channel);

  p4serverv1::Config config;
  config.mutable_stream()->set_error_reporting(
      p4serverv1::StreamConfig::DETAILED);

  {
    p4serverv1::SetRequest request;
    request.set_device_id(device_id);
    request.mutable_config()->CopyFrom(config);
    ClientContext context;
    p4serverv1::SetResponse response;
    EXPECT_TRUE(stub->Set(&context, request, &response).ok());
  }

  {
    p4serverv1::GetRequest request;
    request.set_device_id(device_id);
    ClientContext context;
    p4serverv1::GetResponse response;
    EXPECT_TRUE(stub->Get(&context, request, &response).ok());
    EXPECT_PROTO_EQ(response.config(), config);
  }
}

}  // namespace testing
}  // namespace proto
}  // namespace pi
