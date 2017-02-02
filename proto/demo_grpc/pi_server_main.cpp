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

#include "pi_server.h"

#include <iostream>

#include <csignal>

using pi::fe::proto::DeviceMgr;

int main(int argc, char** argv) {
  DeviceMgr::init(256);

  auto handler = [](int s) {
    std::cout << "Server shutting down\n";
    PIGrpcServerShutdown();
  };

  PIGrpcServerRun();

  // TODO(antonin): use sigaction?
  std::signal(SIGINT, handler);
  std::signal(SIGTERM, handler);
  std::signal(SIGQUIT, handler);

  PIGrpcServerWait();
  PIGrpcServerCleanup();

  DeviceMgr::destroy();

  return 0;
}
