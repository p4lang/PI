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

#include "p4_config_repo.h"

#include <Judy.h>

static Pvoid_t repo = (Pvoid_t)NULL;

p4_config_id_t p4_config_add(pi_p4info_t *p4info) {
  int Rc_int;
  Word_t index = 0;
  JLFE(Rc_int, repo, index);
  assert(Rc_int == 1);
  Word_t *p4info_ptr = NULL;
  JLI(p4info_ptr, repo, index);
  assert(p4info_ptr && *p4info_ptr == 0);
  *p4info_ptr = (Word_t)p4info;
  return index;
}

pi_p4info_t *p4_config_get(p4_config_id_t id) {
  Word_t *p4info_ptr = NULL;
  JLG(p4info_ptr, repo, (Word_t)id);
  if (!p4info_ptr) return NULL;
  return (pi_p4info_t *)*p4info_ptr;
}

pi_p4info_t *p4_config_get_first() {
  Word_t index = 0;
  Word_t *p4info_ptr = NULL;
  JLF(p4info_ptr, repo, index);
  if (!p4info_ptr) return NULL;
  return (pi_p4info_t *)*p4info_ptr;
}

void p4_config_cleanup() {
  Word_t index = 0;
  Word_t *p4info_ptr = NULL;
  JLF(p4info_ptr, repo, index);
  while (p4info_ptr) {
    pi_destroy_config((pi_p4info_t *)*p4info_ptr);
    JLN(p4info_ptr, repo, index);
  }
  Word_t cnt;
// there is code in Judy headers that raises a warning with some compiler
// versions
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wsign-compare"
  JLFA(cnt, repo);
#pragma GCC diagnostic pop
}
