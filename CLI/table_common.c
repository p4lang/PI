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
#include "table_common.h"

#include "PI/pi.h"
#include "PI/frontends/generic/pi.h"

#include <string.h>
#include <stdlib.h>

#include <readline/readline.h>

#define BYTES_TEMP_SIZE 64

pi_cli_status_t read_action_data(char *in, pi_p4_id_t a_id,
                                 pi_action_data_t *adata) {
  size_t num_params;
  const pi_p4_id_t *param_ids = pi_p4info_action_get_params(p4info, a_id,
                                                            &num_params);
  for (size_t i = 0; i < num_params; i++) {
    pi_p4_id_t p_id = param_ids[i];
    size_t p_bitwidth = pi_p4info_action_param_bitwidth(p4info, p_id);
    char *ap = strtok(in, " ");
    in = NULL;
    if (!ap || ap[0] == '=') return PI_CLI_STATUS_TOO_FEW_ACTION_PARAMS;

    char bytes[BYTES_TEMP_SIZE];
    if (param_to_bytes(ap, bytes, p_bitwidth)) return 1;
    pi_netv_t p_netv;
    pi_status_t rc;
    rc = pi_getnetv_ptr(p4info, p_id, bytes, (p_bitwidth + 7) / 8, &p_netv);
    assert(rc == PI_STATUS_SUCCESS);
    rc = pi_action_data_arg_set(p4info, adata, &p_netv);
    assert(rc == PI_STATUS_SUCCESS);
  }

  return PI_CLI_STATUS_SUCCESS;
}

char *complete_table_and_action(const char *text, int state) {
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
