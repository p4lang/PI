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

#include <PI/pi.h>

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
