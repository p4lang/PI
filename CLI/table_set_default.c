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
#include "table_common.h"
#include "utils.h"

#include "PI/frontends/generic/pi.h"
#include "PI/pi.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char table_set_default_hs[] =
    "Set default entry in a match table: "
    "table_set_default <table name> "
    "[<action name> <action parameters> | <indirect handle>]";

pi_cli_status_t do_table_set_default(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info_curr, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;

  pi_cli_status_t status;

  pi_p4_id_t t_imp = pi_p4info_table_get_implementation(p4info_curr, t_id);

  pi_table_entry_t t_entry;
  if (t_imp == PI_INVALID_ID) {
    status = get_entry_direct(&t_entry);
  } else {
    status = get_entry_indirect(&t_entry);
  }
  if (status != PI_CLI_STATUS_SUCCESS) {
    return status;
  }

  t_entry.entry_properties = NULL;
  t_entry.direct_res_config = NULL;

  pi_status_t rc;
  rc = pi_table_default_action_set(sess, dev_tgt, t_id, &t_entry);
  if (rc == PI_STATUS_SUCCESS)
    printf("Default entry was successfully set.\n");
  else
    printf("Error when trying to set default entry.\n");

  if (t_imp == PI_INVALID_ID)
    cleanup_entry_direct(&t_entry);
  else
    cleanup_entry_indirect(&t_entry);

  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_set_default(const char *text, int state) {
  return complete_table(text, state);
}
