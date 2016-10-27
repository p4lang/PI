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

#include "func_counter.h"

#include <Judy.h>

#include <stdio.h>

typedef struct { Pvoid_t array; } func_counter_t;

static func_counter_t func_counter;

void func_counter_init() { func_counter.array = (Pvoid_t)NULL; }

void func_counter_increment(const char *func_name) {
#ifdef DEBUG
  printf("%s\n", func_name);
#endif
  Word_t *PValue;
  JSLI(PValue, func_counter.array, (const uint8_t *)func_name);
  (*PValue)++;
}

int func_counter_get(const char *func_name) {
  Word_t *PValue;
  JSLG(PValue, func_counter.array, (const uint8_t *)func_name);
  return (PValue == NULL) ? -1 : (int)*PValue;
}

int func_counter_dump_to_file(const char *path) {
  FILE *f = fopen(path, "w");
  if (f == NULL) return 1;
  Word_t *PValue;
  uint8_t index[128];  // max function name must be 128 bytes
  index[0] = 0;
  JSLF(PValue, func_counter.array, index);
  while (PValue != NULL) {
    fprintf(f, "%s : %d\n", (char *)index, (int)*PValue);
    JSLN(PValue, func_counter.array, index);
  }
  fclose(f);
  return 0;
}

void func_counter_destroy() {
  Word_t bytes_freed = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wsign-compare"
  JSLFA(bytes_freed, func_counter.array);
#pragma GCC diagnostic pop
  (void)bytes_freed;
}
