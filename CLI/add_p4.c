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

#include "utils.h"
#include "error_codes.h"
#include "p4_config_repo.h"

#include <PI/pi.h>

#include <string.h>
#include <stdlib.h>

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
