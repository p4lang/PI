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

char table_set_default_hs[] =
    "Set default entry in a match table: "
    "table_set_default <table name> <action name> <action parameters>";

pi_cli_status_t do_table_set_default(char *subcmd) {
  const char *args[2];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  const char *a_name = args[1];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, a_name);
  if (a_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_ACTION_NAME;

  pi_cli_status_t status;

  pi_action_data_t *adata;
  pi_action_data_allocate(p4info, a_id, &adata);
  pi_action_data_init(adata);
  status = read_action_data(NULL, a_id, adata);
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_action_data_destroy(adata);
    return status;
  }

  pi_table_entry_t t_entry;
  t_entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  t_entry.entry.action_data = adata;
  t_entry.entry_properties = NULL;
  t_entry.direct_res_config = NULL;

  pi_status_t rc;
  rc = pi_table_default_action_set(sess, dev_tgt, t_id, &t_entry);
  if (rc == PI_STATUS_SUCCESS)
    printf("Default entry was successfully set.\n");
  else
    printf("Error when trying to set default entry.\n");

  pi_action_data_destroy(adata);
  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
      : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_set_default(const char *text, int state) {
  return complete_table_and_action(text, state);
}
