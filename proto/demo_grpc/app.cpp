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

#include "simple_router_mgr.h"
#include "web_server.h"

#include <PI/pi.h>

#include <boost/asio.hpp>

#include <ctype.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <streambuf>
#include <thread>

#define PORT 8888

namespace {

char *opt_config_path = NULL;

void print_help(const char *name) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]...\n"
          "PI example controller app\n\n"
          "-c          P4 config (json)\n",
          name);
}

int parse_opts(int argc, char *const argv[]) {
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "c:h")) != -1) {
    switch (c) {
      case 'c':
        opt_config_path = optarg;
        break;
      case 'h':
        print_help(argv[0]);
        exit(0);
      case '?':
        if (optopt == 'c') {
          fprintf(stderr, "Option -%c requires an argument.\n\n", optopt);
          print_help(argv[0]);
        } else if (isprint(optopt)) {
          fprintf(stderr, "Unknown option `-%c'.\n\n", optopt);
          print_help(argv[0]);
        } else {
          fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
          print_help(argv[0]);
        }
        return 1;
      default:
        abort();
    }
  }

  if (!opt_config_path) {
    fprintf(stderr, "Options -c is required.\n\n");
    print_help(argv[0]);
    return 1;
  }

  int extra_arg = 0;
  for (int index = optind; index < argc; index++) {
    fprintf(stderr, "Non-option argument: %s\n", argv[index]);
    extra_arg = 1;
  }
  if (extra_arg) {
    print_help(argv[0]);
    return 1;
  }

  return 0;
}

}  // namespace

int main(int argc, char *argv[]) {
  if (parse_opts(argc, argv) != 0) return 1;

  boost::asio::io_service io_service;
  boost::asio::io_service::work work(io_service);

  auto channel = grpc::CreateChannel(
      "localhost:50051", grpc::InsecureChannelCredentials());

  int dev_id = 0;
  SimpleRouterMgr simple_router_mgr(dev_id, io_service, channel);
  std::ifstream istream(opt_config_path);
  std::string config((std::istreambuf_iterator<char>(istream)),
                      std::istreambuf_iterator<char>());
  auto rc = simple_router_mgr.assign(config);
  (void) rc;
  assert(rc == 0);
  simple_router_mgr.set_default_entries();
  simple_router_mgr.static_config();

  // TODO(antonin): manage web server requests in same boost asio event loop?
  WebServer web_server(&simple_router_mgr);
  web_server.set_json_name(std::string(opt_config_path));
  web_server.start();

  io_service.run();
  assert(0);
}
