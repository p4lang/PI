/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

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
  pi_p4info_t *p4info;
  pi_add_config_from_file(opt_config_path, PI_CONFIG_TYPE_BMV2_JSON, &p4info);

  boost::asio::io_service io_service;
  boost::asio::io_service::work work(io_service);

  auto channel = grpc::CreateChannel(
      "localhost:50051", grpc::InsecureChannelCredentials());

  SimpleRouterMgr::init(256, channel);

  int dev_id = 0;
  SimpleRouterMgr simple_router_mgr(dev_id, p4info, io_service, channel);
  assert(!simple_router_mgr.assign());
  simple_router_mgr.set_default_entries();
  simple_router_mgr.static_config();

  // TODO(antonin): manage web server requests in same boost asio event loop?
  WebServer web_server(&simple_router_mgr);
  web_server.set_json_name(std::string(opt_config_path));
  web_server.start();

  simple_router_mgr.start_processing_packets();

  io_service.run();
  assert(0);
}
