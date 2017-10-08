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

#include "error_codes.h"
#include "p4_config_repo.h"
#include "utils.h"

#include <PI/pi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <readline/readline.h>

extern pi_p4info_t *p4info;

#define MAX_EXTRAS 16

char add_p4_hs[] =
    "Add a P4 configuration and receive an ID for it, "
    "default config type is bmv2: "
    "add_p4 <path_to_config> [bmv2|native]*";

pi_cli_status_t do_add_p4(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *config_path = args[0];

  char *config_type_str = strtok(NULL, " ");
  pi_config_type_t config_type = PI_CONFIG_TYPE_BMV2_JSON;
  if (config_type_str) {
    if (!strncmp(config_type_str, "bmv2", sizeof "bmv2")) {
      config_type = PI_CONFIG_TYPE_BMV2_JSON;
    } else if (!strncmp(config_type_str, "native", sizeof "native")) {
      config_type = PI_CONFIG_TYPE_NATIVE_JSON;
    } else {
      fprintf(stderr, "Invalid config type, must be one of bmv2 | native.\n");
      return PI_CLI_STATUS_INVALID_P4_CONFIG_TYPE;
    }
  }

  pi_p4info_t *new_p4info;
  pi_status_t pirc =
      pi_add_config_from_file(config_path, config_type, &new_p4info);
  if (pirc != PI_STATUS_SUCCESS) {
    fprintf(stderr, "Error while loading config\n");
    return PI_CLI_STATUS_INVALID_P4_CONFIG;
  }

  p4_config_id_t p4_config_id = p4_config_add(new_p4info);
  printf("P4 config added with id %d\n", p4_config_id);

  return PI_CLI_STATUS_SUCCESS;
}
