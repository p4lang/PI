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

#include "p4info_struct.h"

void p4info_init_res(pi_p4info_t *p4info, int res_type, size_t num,
                     size_t e_size, P4InfoFreeOneFn free_fn,
                     P4InfoSerializeFn serialize_fn) {
  pi_p4info_res_t *res = &p4info->resources[res_type];
  res->is_init = 1;
  res->free_fn = free_fn;
  res->serialize_fn = serialize_fn;
  p4info_array_create(&res->arr, e_size, num);
  res->name_map = (p4info_name_map_t)NULL;
}
