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

#include <stdint.h>
#include <string.h>

size_t emit_uint32(char *dst, uint32_t v) {
  memcpy(dst, &v, sizeof(v));
  return sizeof(v);
}

size_t emit_uint64(char *dst, uint64_t v) {
  memcpy(dst, &v, sizeof(v));
  return sizeof(v);
}

size_t retrieve_uint32(const char *src, uint32_t *v) {
  memcpy(v, src, sizeof(*v));
  return sizeof(*v);
}

size_t retrieve_uint64(const char *src, uint64_t *v) {
  memcpy(v, src, sizeof(*v));
  return sizeof(*v);
}
