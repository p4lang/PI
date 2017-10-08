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

#include <readline/readline.h>

char table_delete_hs[] =
    "Delete entry from a match table: table_delete <table name> <entry handle>";

pi_cli_status_t do_table_delete(char *subcmd) {
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

  pi_status_t rc;
  rc = pi_table_entry_delete(sess, dev_tgt.dev_id, t_id, handle);
  if (rc == PI_STATUS_SUCCESS)
    printf("Entry with handle %" PRIu64 " was successfully removed.\n", handle);
  else
    printf("Error when trying to remove entry %" PRIu64 ".\n", handle);

  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_delete(const char *text, int state) {
  return complete_table(text, state);
}

char table_delete_wkey_hs[] =
    "Delete entry from a match table using the match key: "
    "table_delete_wkey <table name> <match fields> [priority]";

pi_cli_status_t do_table_delete_wkey(char *subcmd) {
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
  status = read_match_key_with_priority(NULL, t_id, mk, NULL);
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_match_key_destroy(mk);
    return status;
  }

  pi_status_t rc;
  rc = pi_table_entry_delete_wkey(sess, dev_tgt.dev_id, t_id, mk);
  if (rc == PI_STATUS_SUCCESS)
    printf("Entry was successfully removed.\n");
  else
    printf("Error when trying to remove entry.\n");

  pi_match_key_destroy(mk);

  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_delete_wkey(const char *text, int state) {
  return complete_table(text, state);
}
