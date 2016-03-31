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

#include "PI/pi.h"

#include <string.h>

int count_tokens(const char *str) {
  int count = 0;
  const char *ptr = str;
  while((ptr = strchr(ptr, ' ')) != NULL) {
    count++;
    ptr++;
  }
  return count;
}

// TODO(antonin): make this method robust
char *get_token_from_buffer(char *buffer, size_t index) {
  char *e = buffer;
  for (size_t i = 0; i < index; i++) {
    e = strchr(e, ' ');
    e++;
  }
  e = strdup(e);
  char *c = strchr(e, ' ');
  if (c) *c = '\0';
  return e;
}

extern pi_p4info_t *p4info;

char *complete_p4_table(const char *text, int len, int state) {
  static pi_p4_id_t id;
  if (!state) id = pi_p4info_table_begin(p4info);
  while (id != pi_p4info_table_end(p4info)) {
    const char *name = pi_p4info_table_name_from_id(p4info, id);
    id = pi_p4info_table_next(p4info, id);
    if (!strncmp(name, text, len)) return strdup(name);
  }
  return NULL;
}
#include <stdio.h>
char *complete_p4_action(const char *text, int len, int state,
                         const char *table) {
  static pi_p4_id_t t_id;
  static const pi_p4_id_t *actions;
  static size_t num_actions;
  static size_t index;
  if (!state) {
    t_id = pi_p4info_table_id_from_name(p4info, table);
    if (t_id == PI_INVALID_ID) return NULL;
    actions = pi_p4info_table_get_actions(p4info, t_id, &num_actions);
    index = 0;
  } else if (t_id == PI_INVALID_ID) {
    return NULL;
  }
  assert(actions);

  while (index < num_actions) {
    const char *name = pi_p4info_action_name_from_id(p4info, actions[index]);
    index++;
    if (!strncmp(name, text, len)) return strdup(name);
  }
  return NULL;
}

size_t parse_fixed_args(char *s, const char **dest, size_t expected) {
  for (size_t i = 0; i < expected; i++) {
    dest[i] = (i == 0) ? strtok(s, " ") : strtok(NULL, " ");
    if (!dest[i]) return i;
  }
  return expected;
}
