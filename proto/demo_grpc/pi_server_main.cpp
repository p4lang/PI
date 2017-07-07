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

#include <PI/frontends/proto/device_mgr.h>

#include <PI/proto/pi_server.h>

#include <iostream>

#include <csignal>

using pi::fe::proto::DeviceMgr;

int main(int argc, char** argv) {
  const char *server_address = "0.0.0.0:50051";
  if (argc > 2) {
    std::cerr << "Two many arguments.\n";
    std::cerr << "Usage: " << argv[0]
              << " [address (default " << server_address << ")].\n";
    return 1;
  } else if (argc == 2) {
    server_address = argv[1];
  }

  DeviceMgr::init(256);

  auto handler = [](int s) {
    std::cout << "Server shutting down\n";
    PIGrpcServerForceShutdown(1);  // 1 second deadline
  };

  PIGrpcServerRunAddr(server_address);

  // TODO(antonin): use sigaction?
  std::signal(SIGINT, handler);
  std::signal(SIGTERM, handler);
  std::signal(SIGQUIT, handler);

  PIGrpcServerWait();
  PIGrpcServerCleanup();

  DeviceMgr::destroy();

  return 0;
}
