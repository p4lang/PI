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
#include "table_common.h"
#include "utils.h"

#include "PI/frontends/generic/pi.h"
#include "PI/pi.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char act_prof_create_member_hs[] =
    "Add a member to an action profile: "
    "act_prof_create_member <act_prof_name> <action_name> "
    "[action parameters]";

pi_cli_status_t do_act_prof_create_member(char *subcmd) {
  const char *args[2];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *act_prof_name = args[0];
  const char *action_name = args[1];
  pi_p4_id_t act_prof_id =
      pi_p4info_act_prof_id_from_name(p4info_curr, act_prof_name);
  if (act_prof_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;
  pi_p4_id_t action_id =
      pi_p4info_action_id_from_name(p4info_curr, action_name);
  if (action_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_ACTION_NAME;

  pi_cli_status_t status;

  pi_action_data_t *adata;
  pi_action_data_allocate(p4info_curr, action_id, &adata);
  pi_action_data_init(adata);
  status = read_action_data(NULL, action_id, adata);
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_action_data_destroy(adata);
    return status;
  }

  pi_indirect_handle_t mbr_handle = 0;
  pi_status_t rc;
  rc = pi_act_prof_mbr_create(sess, dev_tgt, act_prof_id, adata, &mbr_handle);
  if (rc == PI_STATUS_SUCCESS) {
    printf("Member was successfully created with handle %" PRIu64 ".\n",
           mbr_handle);
  } else {
    printf("Error when trying to create member.\n");
  }

  pi_action_data_destroy(adata);
  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_act_prof_create_member(const char *text, int state) {
  return complete_act_prof_and_action(text, state);
}
