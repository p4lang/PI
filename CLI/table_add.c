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

#include "PI/pi.h"
#include "PI/frontends/generic/pi.h"

#include <string.h>
#include <stdlib.h>

#include <readline/readline.h>

extern pi_p4info_t *p4info;

char table_add_hs[] =
    "Add entry to a match table: "
    "table_add <table name> <action name> <match fields> => "
    "<action parameters> [priority]";

pi_cli_status_t do_table_add(char *subcmd) {
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

  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, t_id);
  for (size_t i = 0; i < num_match_fields; i++) {
    pi_p4info_match_field_info_t finfo;
    pi_p4info_table_match_field_info(p4info, t_id, i, &finfo);
    (void) finfo;
  }
  
  return PI_CLI_STATUS_SUCCESS;
};

char *complete_table_add(const char *text, int state) {
  static int token_count;
  static int len;
  static char *t_name;

  if (!state) {
    token_count = count_tokens(rl_line_buffer);
    len = strlen(text);
    if (t_name) free(t_name);
    t_name = NULL;
  }

  if (token_count == 0) {  // just the cmd
    return NULL;
  } else if (token_count == 1) {
    return complete_p4_table(text, len, state);
  } else if (token_count == 2) {
    if (!t_name) t_name = get_token_from_buffer(rl_line_buffer, 1);
    assert(t_name);
    return complete_p4_action(text, len, state, t_name);
  }
  return NULL;
}
