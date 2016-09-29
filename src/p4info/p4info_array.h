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

#ifndef PI_SRC_P4INFO_P4INFO_ARRAY_H_
#define PI_SRC_P4INFO_P4INFO_ARRAY_H_

#include <stddef.h>

typedef void (*P4InfoFreeOneFn)(void *);

typedef struct p4info_array_s {
  size_t e_size;
  size_t size;
  void *data;
} p4info_array_t;

void p4info_array_create(p4info_array_t *v, size_t e_size, size_t size);

void p4info_array_destroy(p4info_array_t *v, P4InfoFreeOneFn free_fn);

void *p4info_array_at(const p4info_array_t *v, size_t index);

size_t p4info_array_size(const p4info_array_t *v);

#endif  // PI_SRC_P4INFO_P4INFO_ARRAY_H_
