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

#include "p4info_array.h"

#include <stdlib.h>
#include <assert.h>

void p4info_array_create(p4info_array_t *v, size_t e_size, size_t size) {
  assert(e_size > 0);
  v->e_size = e_size;
  v->size = size;
  v->data = calloc(size, e_size);
}

static void *access(const p4info_array_t *v, size_t index) {
  return (char *)v->data + (index * v->e_size);
}

void p4info_array_destroy(p4info_array_t *v, P4InfoFreeOneFn free_fn) {
  if (free_fn != NULL) {
    for (size_t index = 0; index < v->size; index++) {
      free_fn(access(v, index));
    }
  }
  free(v->data);
}

void *p4info_array_at(const p4info_array_t *v, size_t index) {
  assert(index < v->size);
  return access(v, index);
}

size_t p4info_array_size(const p4info_array_t *v) { return v->size; }
