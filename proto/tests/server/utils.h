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

#ifndef PROTO_TESTS_SERVER_UTILS_H_
#define PROTO_TESTS_SERVER_UTILS_H_

#include <PI/proto/pi_server.h>

#include <string>

namespace pi {
namespace proto {
namespace testing {

class TestServer {
 public:
  TestServer() {
    PIGrpcServerRunAddr(bind_any_addr);
    server_port = PIGrpcServerGetPort();
  }

  ~TestServer() {
    PIGrpcServerShutdown();
  }

  std::string bind_addr() const {
    return std::string("0.0.0.0:") + std::to_string(server_port);
  }

 private:
  static constexpr char bind_any_addr[] = "[::]:0";
  int server_port;
};

}  // namespace testing
}  // namespace proto
}  // namespace pi

#endif  // PROTO_TESTS_SERVER_UTILS_H_
