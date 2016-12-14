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

// Generates the PI JSON from the Bmv2 JSON

#include <PI/p4info.h>
#include <PI/pi.h>

#include <stdio.h>
#include <stdlib.h>

// TODO(antonin): this is just temporary, to ensure no logs go to stdout
extern void pi_logs_off();

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "P4 configuration needed.\n");
    fprintf(stderr, "Usage: %s <path to config>\n", argv[0]);
    return 1;
  }

  pi_logs_off();

  pi_status_t status;
  pi_p4info_t *p4info;
  status = pi_add_config_from_file(argv[1], PI_CONFIG_TYPE_BMV2_JSON, &p4info);
  if (status != PI_STATUS_SUCCESS) {
    fprintf(stderr, "Error while loading config.\n");
    return 1;
  }

  char *native_json = pi_serialize_config(p4info, 1);

  printf("%s\n", native_json);

  pi_destroy_config(p4info);
  free(native_json);

  return 0;
}
