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

char table_reset_default_hs[] =
    "Reset default entry in a match table: "
    "table_set_default <table name>";

pi_cli_status_t do_table_reset_default(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info_curr, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;

  pi_status_t rc = pi_table_default_action_reset(sess, dev_tgt, t_id);
  if (rc == PI_STATUS_SUCCESS) {
    printf("Default entry was successfully reset.\n");
    return PI_CLI_STATUS_SUCCESS;
  } else {
    printf("Error when trying to reset default entry.\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }
};

char *complete_table_reset_default(const char *text, int state) {
  return complete_table(text, state);
}
