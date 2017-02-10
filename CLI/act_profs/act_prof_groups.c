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

#include "act_prof_common.h"
#include "error_codes.h"
#include "utils.h"

#include "PI/frontends/generic/pi.h"
#include "PI/pi.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char act_prof_create_group_hs[] =
    "Add group to an action profile: "
    "act_prof_create_group <act_prof_name> [grp_size = 120]";

pi_cli_status_t do_act_prof_create_group(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *act_prof_name = args[0];
  pi_p4_id_t act_prof_id =
      pi_p4info_act_prof_id_from_name(p4info_curr, act_prof_name);
  if (act_prof_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;

  size_t grp_size = 120;
  char *token = strtok(NULL, " ");
  if (token) {
    char *endptr;
    grp_size = strtol(token, &endptr, 0);
    if (*endptr != '\0') return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  }

  pi_indirect_handle_t grp_handle = 0;
  pi_status_t rc;
  rc =
      pi_act_prof_grp_create(sess, dev_tgt, act_prof_id, grp_size, &grp_handle);
  if (rc == PI_STATUS_SUCCESS) {
    printf("Group was successfully created with handle %" PRIu64 ".\n",
           grp_handle);
  } else {
    printf("Error when trying to create group.\n");
  }
  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_act_prof_create_group(const char *text, int state) {
  return complete_act_prof(text, state);
}

char act_prof_add_member_to_group_hs[] =
    "Add member to a group in an action profile: "
    "act_prof_add_member_to_group <act_prof_name> <mbr_h> <grp_h>";

pi_cli_status_t do_act_prof_add_member_to_group(char *subcmd) {
  const char *args[3];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *act_prof_name = args[0];
  pi_p4_id_t act_prof_id =
      pi_p4info_act_prof_id_from_name(p4info_curr, act_prof_name);
  if (act_prof_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;
  pi_indirect_handle_t mbr_h, grp_h;
  char *endptr;
  mbr_h = strtoll(args[1], &endptr, 0);
  if (*endptr != '\0') return PI_CLI_STATUS_INVALID_ENTRY_HANDLE;
  grp_h = strtoll(args[1], &endptr, 0);
  if (*endptr != '\0') return PI_CLI_STATUS_INVALID_ENTRY_HANDLE;

  pi_status_t rc;
  rc = pi_act_prof_grp_add_mbr(sess, dev_tgt.dev_id, act_prof_id, grp_h, mbr_h);
  if (rc == PI_STATUS_SUCCESS)
    printf("Member was successfully added to group.\n");
  else
    printf("Error when trying to add member to group.\n");
  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_act_prof_add_member_to_group(const char *text, int state) {
  return complete_act_prof(text, state);
}
