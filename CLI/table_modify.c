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

#include "utils.h"
#include "error_codes.h"
#include "table_common.h"

#include "PI/pi.h"
#include "PI/frontends/generic/pi.h"

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>

char table_modify_hs[] =
    "Modify entry in a match table: "
    "table_modify <table name> <action name> <entry_handle> "
    "<action parameters>";

pi_cli_status_t do_table_modify(char *subcmd) {
  const char *args[3];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  const char *a_name = args[1];
  const char *handle_str = args[2];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, a_name);
  if (a_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_ACTION_NAME;
  char *endptr;
  pi_entry_handle_t handle = strtoll(handle_str, &endptr, 0);
  if (*endptr != '\0') return PI_CLI_STATUS_INVALID_ENTRY_HANDLE;

  pi_cli_status_t status;

  pi_action_data_t *adata;
  pi_action_data_allocate(p4info, a_id, &adata);
  pi_action_data_init(adata);
  status = read_action_data(NULL, a_id, adata);
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_action_data_destroy(adata);
    return status;
  }

  pi_table_entry_t t_entry = {a_id, adata, NULL, NULL};
  pi_status_t rc;
  rc = pi_table_entry_modify(dev_tgt.dev_id, t_id, handle, &t_entry);
  if (rc == PI_STATUS_SUCCESS)
    printf("Entry with handle %" PRIu64 " was successfully modified.\n",
           handle);
  else
    printf("Error when trying to modify entry %" PRIu64 ".\n", handle);

  pi_action_data_destroy(adata);
  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
      : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_modify(const char *text, int state) {
  return complete_table_and_action(text, state);
}
