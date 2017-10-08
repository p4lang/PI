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

#include "utils.h"

#include "PI/p4info.h"
#include "PI/pi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <readline/readline.h>

extern const pi_p4info_t *p4info_curr;

static char *complete_p4_act_prof(const char *text, int len, int state) {
  static pi_p4_id_t id;
  if (!state) id = pi_p4info_act_prof_begin(p4info_curr);
  while (id != pi_p4info_act_prof_end(p4info_curr)) {
    const char *name = pi_p4info_act_prof_name_from_id(p4info_curr, id);
    id = pi_p4info_act_prof_next(p4info_curr, id);
    if (!strncmp(name, text, len)) return strdup(name);
  }
  return NULL;
}

// get one of the tables for the action profile, to retrieve the actions
static char *get_one_act_prof_table(const char *act_prof_name) {
  pi_p4_id_t act_prof_id =
      pi_p4info_act_prof_id_from_name(p4info_curr, act_prof_name);
  if (act_prof_id == PI_INVALID_ID) return NULL;
  size_t num_tables = 0;
  const pi_p4_id_t *t_ids =
      pi_p4info_act_prof_get_tables(p4info_curr, act_prof_id, &num_tables);
  assert(num_tables > 0);
  assert(*t_ids != PI_INVALID_ID);
  return strdup(pi_p4info_table_name_from_id(p4info_curr, *t_ids));
}

char *complete_act_prof(const char *text, int state) {
  static int token_count;
  static int len;

  if (!state) {
    token_count = count_tokens(rl_line_buffer);
    len = strlen(text);
  }

  if (token_count == 0) {  // just the cmd
    return NULL;
  } else if (token_count == 1) {
    return complete_p4_act_prof(text, len, state);
  }
  return NULL;
}

char *complete_act_prof_and_action(const char *text, int state) {
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
    return complete_p4_act_prof(text, len, state);
  } else if (token_count == 2) {
    if (!t_name) {
      char *act_prof_name = get_token_from_buffer(rl_line_buffer, 1);
      assert(act_prof_name);
      t_name = get_one_act_prof_table(act_prof_name);
      if (!t_name) return NULL;
    }
    assert(t_name);
    return complete_p4_action(text, len, state, t_name);
  }
  return NULL;
}
