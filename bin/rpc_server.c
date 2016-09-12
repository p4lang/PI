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

#include <PI/pi.h>

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

extern pi_status_t pi_rpc_server_run(const pi_remote_addr_t *remote_addr);

static void cleanup_handler(int signum) {
  (void)signum;
  pi_destroy();
}

// command-line options
static char *opt_rpc_addr = NULL;
static char *opt_notifications_addr = NULL;

static void print_help(const char *name) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]...\n"
          "PI RPC server\n\n"
          "-a          nanomsg address for RPC\n"
          "-n          nanomsg address for notifications\n",
          name);
}

static int parse_opts(int argc, char *const argv[]) {
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "a:n:h")) != -1) {
    switch (c) {
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
        if (optopt == 'a' || optopt == 'n') {
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

int main(int argc, char *argv[]) {
  if (parse_opts(argc, argv) != 0) return 1;

  pi_init(256, NULL);

  struct sigaction sa;
  sa.sa_handler = cleanup_handler;
  // sigfillset(&sa.sa_mask);
  sigemptyset(&sa.sa_mask);
  // Restart the system call, if at all possible
  sa.sa_flags = SA_RESTART;
  assert(sigaction(SIGHUP, &sa, NULL) == 0);
  assert(sigaction(SIGINT, &sa, NULL) == 0);
  assert(sigaction(SIGTERM, &sa, NULL) == 0);

  pi_remote_addr_t remote_addr = {opt_rpc_addr, opt_notifications_addr};
  pi_rpc_server_run(&remote_addr);
}
