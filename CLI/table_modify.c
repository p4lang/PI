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

static pi_cli_status_t get_entry_with_res(
    pi_p4_id_t t_id, pi_table_entry_t *t_entry,
    pi_direct_res_config_t *direct_res_config) {
  pi_cli_status_t status;
  pi_p4_id_t t_imp = pi_p4info_table_get_implementation(p4info_curr, t_id);

  if (t_imp == PI_INVALID_ID)
    status = get_entry_direct(t_entry);
  else
    status = get_entry_indirect(t_entry);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  t_entry->entry_properties = NULL;

  // direct resources
  direct_res_config->configs =
      retrieve_direct_resource_configs(&direct_res_config->num_configs);
  t_entry->direct_res_config = direct_res_config;

  return PI_CLI_STATUS_SUCCESS;
}

static void cleanup_entry_with_res(pi_p4_id_t t_id, pi_table_entry_t *t_entry) {
  pi_p4_id_t t_imp = pi_p4info_table_get_implementation(p4info_curr, t_id);
  if (t_imp == PI_INVALID_ID)
    cleanup_entry_direct(t_entry);
  else
    cleanup_entry_indirect(t_entry);
  reset_direct_resource_configs();
}

char table_modify_hs[] =
    "Modify entry in a match table: "
    "table_modify <table name> <entry_handle> => "
    "[<action name> <action parameters> | <indirect handle>]";

pi_cli_status_t do_table_modify(char *subcmd) {
  const char *args[2];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  const char *handle_str = args[1];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info_curr, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;

  char *endptr;
  pi_entry_handle_t handle = strtoll(handle_str, &endptr, 0);
  if (*endptr != '\0') return PI_CLI_STATUS_INVALID_ENTRY_HANDLE;

  char *separator = strtok(NULL, " ");
  if (!separator || strncmp("=>", separator, sizeof("=>"))) {
    fprintf(stderr, "Use '=>' to separate action data from entry handle.\n");
    return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  }

  pi_cli_status_t status;
  pi_table_entry_t t_entry;
  pi_direct_res_config_t direct_res_config;
  status = get_entry_with_res(t_id, &t_entry, &direct_res_config);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  pi_status_t rc;
  rc = pi_table_entry_modify(sess, dev_tgt.dev_id, t_id, handle, &t_entry);
  if (rc == PI_STATUS_SUCCESS)
    printf("Entry with handle %" PRIu64 " was successfully modified.\n",
           handle);
  else
    printf("Error when trying to modify entry %" PRIu64 ".\n", handle);

  cleanup_entry_with_res(t_id, &t_entry);

  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_modify(const char *text, int state) {
  return complete_table(text, state);
}

char table_modify_wkey_hs[] =
    "Modify entry in a match table using the match key: "
    "table_modify_wkey <table name> <match fields> [priority] => "
    "[<action name> <action parameters> | <indirect handle>]";

pi_cli_status_t do_table_modify_wkey(char *subcmd) {
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

  pi_table_entry_t t_entry;
  pi_direct_res_config_t direct_res_config;
  status = get_entry_with_res(t_id, &t_entry, &direct_res_config);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  pi_status_t rc;
  rc = pi_table_entry_modify_wkey(sess, dev_tgt.dev_id, t_id, mk, &t_entry);
  if (rc == PI_STATUS_SUCCESS)
    printf("Entry was successfully modified.\n");
  else
    printf("Error when trying to modify entry.\n");

  pi_match_key_destroy(mk);
  cleanup_entry_with_res(t_id, &t_entry);

  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_modify_wkey(const char *text, int state) {
  return complete_table(text, state);
}
