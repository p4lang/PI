/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
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
 * Antonin Bas
 *
 */

#include "func_counter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uthash.h>

typedef struct {
  const char *name;
  int counter;
  UT_hash_handle hh;
} counter_t;

static counter_t *func_counter;

void func_counter_init() { func_counter = NULL; }

void func_counter_increment(const char *func_name) {
#ifdef DEBUG
  printf("%s\n", func_name);
#endif
  counter_t *c;
  HASH_FIND_STR(func_counter, func_name, c);
  if (!c) {
    c = malloc(sizeof(*c));
    c->name = func_name;
    c->counter = 0;
    HASH_ADD_KEYPTR(hh, func_counter, c->name, strlen(c->name), c);
  }
  c->counter++;
}

int func_counter_get(const char *func_name) {
  counter_t *c;
  HASH_FIND_STR(func_counter, func_name, c);
  return (c == NULL) ? -1 : c->counter;
}

int func_counter_dump_to_file(const char *path) {
  FILE *f = fopen(path, "w");
  if (f == NULL) return 1;
  counter_t *c;
  for (c = func_counter; c != NULL; c = c->hh.next) {
    fprintf(f, "%s : %d\n", c->name, c->counter);
  }
  fclose(f);
  return 0;
}

void func_counter_destroy() {
  counter_t *c, *tmp;
  HASH_ITER(hh, func_counter, c, tmp) {  // deletion-safe iteration
    HASH_DEL(func_counter, c);
    free(c);
  }
}
