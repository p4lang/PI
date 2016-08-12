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

#include <stdio.h>

extern pi_status_t pi_rpc_server_run();

int main(int argc, char *argv[]) {
  char *addr = NULL;
  if (argc == 1) {
    fprintf(stderr, "Nanomsg address not provided, using default.\n");
  } else if (argc == 2) {
    addr = argv[1];
  } else {
    fprintf(stderr, "Too may arguments provided.\n");
    return 1;
  }

  pi_init(256, NULL);
  pi_rpc_server_run(addr);
}
