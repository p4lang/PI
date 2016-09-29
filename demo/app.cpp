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

#include <iostream>
#include <thread>
#include <chrono>

#define PORT 8888

namespace {

char *opt_rpc_addr = NULL;
char *opt_notifications_addr = NULL;
char *opt_config_path = NULL;

void print_help(const char *name) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]...\n"
          "PI example controller app\n\n"
          "-c          P4 config (json)\n"
          "-a          nanomsg address for RPC\n"
          "-n          nanomsg address for notifications\n",
          name);
}

int parse_opts(int argc, char *const argv[]) {
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "c:a:n:h")) != -1) {
    switch (c) {
      case 'c':
        opt_config_path = optarg;
        break;
      case 'a':
        opt_rpc_addr = optarg;
        break;
      case 'n':
        opt_notifications_addr = optarg;
        break;
      case 'h':
        print_help(argv[0]);
        exit(0);
      case '?':
        if (optopt == 'c' || optopt == 'a' || optopt == 'n') {
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

  if (!opt_config_path || !opt_rpc_addr || !opt_notifications_addr) {
    fprintf(stderr, "Options -c, -a and -n are ALL required.\n\n");
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
  pi_remote_addr_t remote_addr = {opt_rpc_addr, opt_notifications_addr};
  // remote_addr.rpc_addr = (char *)"tcp://127.0.0.1:10111";
  // remote_addr.notifications_addr = (char *)"tcp://127.0.0.1:10112";
  pi_init(256, &remote_addr);  // 256 max devices
  pi_p4info_t *p4info;
  pi_add_config_from_file(opt_config_path, PI_CONFIG_TYPE_BMV2_JSON, &p4info);

  pi_assign_extra_t assign_options[4];
  memset(assign_options, 0, sizeof(assign_options));
  {
    pi_assign_extra_t *rpc_port = &assign_options[0];
    rpc_port->key = "port";
    rpc_port->v = "9090";
  }
  {
    pi_assign_extra_t *notifications_addr = &assign_options[1];
    notifications_addr->key = "notifications";
    notifications_addr->v = "ipc:///tmp/bmv2-0-notifications.ipc";
  }
  {
    pi_assign_extra_t *cpu_iface = &assign_options[2];
    cpu_iface->key = "cpu_iface";
    cpu_iface->v = "veth251";
  }
  assign_options[3].end_of_extras = true;
  pi_assign_device(0, p4info, assign_options);

  boost::asio::io_service io_service;
  boost::asio::io_service::work work(io_service);

  pi_dev_tgt_t dev_tgt = {0, 0xffff};
  SimpleRouterMgr simple_router_mgr(dev_tgt, p4info, io_service);
  simple_router_mgr.set_default_entries();
  simple_router_mgr.static_config();

  // TODO(antonin): manage web server requests in same boost asio event loop?
  WebServer web_server(&simple_router_mgr);
  web_server.set_json_name(std::string(opt_config_path));
  web_server.start();

  simple_router_mgr.start_processing_packets();

  io_service.run();
}
