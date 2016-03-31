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

#include <readline/readline.h>

extern pi_p4info_t *p4info;

char table_delete_hs[] =
    "Delete entry from a match table: table_delete <table name> <entry handle>";

pi_cli_status_t do_table_delete(char *subcmd) {
  (void) subcmd;
  return PI_CLI_STATUS_SUCCESS;
};

char *complete_table_delete(const char *text, int state) {
  static int token_count;
  static int len;

  if (!state) {
    token_count = count_tokens(rl_line_buffer);
    len = strlen(text);
  }

  if (token_count == 0) {  // just the cmd
    return NULL;
  } else if (token_count == 1) {
    return complete_p4_table(text, len, state);
  }
  return NULL;
}
