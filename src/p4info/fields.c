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

#include "PI/p4info/fields.h"

pi_p4_id_t pi_p4info_field_id_from_name(const char *name) {
  (void) name;
  return 0;
}

const char *pi_p4info_field_name_from_id(pi_p4_id_t field_id) {
  (void) field_id;
  return NULL;
}

size_t pi_p4info_field_bitwidth(pi_p4_id_t field_id) {
  (void) field_id;
  return 0;
}
