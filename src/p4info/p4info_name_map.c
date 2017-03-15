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

#include "p4info_name_map.h"

#include <Judy.h>

int p4info_name_map_add(p4info_name_map_t *map, const char *name,
                        pi_p4_id_t id) {
  Word_t *ptr = NULL;
  JSLI(ptr, *map, (const uint8_t *)name);
  if (*ptr != 0) return 0;
  *ptr = id;
  return 1;
}

pi_p4_id_t p4info_name_map_get(const p4info_name_map_t *map, const char *name) {
  Word_t *ptr = NULL;
  JSLG(ptr, *map, (const uint8_t *)name);
  if (!ptr) return PI_INVALID_ID;
  return *ptr;
}

void p4info_name_map_destroy(p4info_name_map_t *map) {
  Word_t Rc_word;
// there is code in Judy headers that raises a warning with some compiler
// versions
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wsign-compare"
  JSLFA(Rc_word, *map);
#pragma GCC diagnostic pop
}
