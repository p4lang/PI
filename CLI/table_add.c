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

char table_add_hs[] =
    "Add entry to a match table: "
    "table_add <table name> <match fields> [priority] => "
    "[<action name> <action parameters> | <indirect handle>]";

pi_cli_status_t do_table_add(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info_curr, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;

  pi_cli_status_t status;

  pi_match_key_t *mk;
  pi_match_key_allocate(p4info_curr, t_id, &mk);
  status = read_match_key_with_priority(NULL, t_id, mk, "=>");
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_match_key_destroy(mk);
    return status;
  }

  pi_p4_id_t t_imp = pi_p4info_table_get_implementation(p4info_curr, t_id);

  pi_table_entry_t t_entry;
  if (t_imp == PI_INVALID_ID) {
    status = get_entry_direct(&t_entry);
  } else {
    status = get_entry_indirect(&t_entry);
  }
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_match_key_destroy(mk);
    return status;
  }

  pi_entry_properties_t entry_properties;
  pi_entry_properties_clear(&entry_properties);
  t_entry.entry_properties = &entry_properties;

  // direct resources
  pi_direct_res_config_t direct_res_config;
  direct_res_config.configs =
      retrieve_direct_resource_configs(&direct_res_config.num_configs);
  t_entry.direct_res_config = &direct_res_config;

  pi_entry_handle_t handle = 0;
  pi_status_t rc;
  rc = pi_table_entry_add(sess, dev_tgt, t_id, mk, &t_entry, 0, &handle);
  if (rc == PI_STATUS_SUCCESS)
    printf("Entry was successfully added with handle %" PRIu64 ".\n", handle);
  else
    printf("Error when trying to add entry.\n");

  pi_match_key_destroy(mk);
  if (t_imp == PI_INVALID_ID)
    cleanup_entry_direct(&t_entry);
  else
    cleanup_entry_indirect(&t_entry);
  reset_direct_resource_configs();

  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_add(const char *text, int state) {
  return complete_table(text, state);
}
