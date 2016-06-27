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

#ifndef PI_INT_SERIALIZE_H_
#define PI_INT_SERIALIZE_H_

#include "PI/pi_base.h"
#include "PI/pi_tables.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t emit_uint32(char *dst, uint32_t v);
size_t emit_uint64(char *dst, uint64_t v);

typedef pi_p4_id_t s_pi_p4_id_t;
typedef pi_entry_handle_t s_pi_entry_handle_t;
typedef uint32_t s_pi_dev_id_t;
typedef struct __attribute__((packed)) {
  s_pi_dev_id_t _dev_id;
  uint32_t _dev_pipe_mask;
} s_pi_dev_tgt_t;
typedef uint32_t s_pi_status_t;
typedef pi_session_handle_t s_pi_session_handle_t;

size_t emit_p4_id(char *dst, pi_p4_id_t v);
size_t emit_entry_handle(char *dst, pi_entry_handle_t v);
size_t emit_dev_id(char *dst, pi_dev_id_t v);
size_t emit_dev_tgt(char *dst, pi_dev_tgt_t v);
size_t emit_status(char *dst, pi_status_t v);
size_t emit_session_handle(char *dst, pi_session_handle_t v);

size_t retrieve_uint32(const char *src, uint32_t *v);
size_t retrieve_uint64(const char *src, uint64_t *v);

size_t retrieve_p4_id(const char *src, pi_p4_id_t *v);
size_t retrieve_entry_handle(const char *src, pi_entry_handle_t *v);
size_t retrieve_dev_id(const char *src, pi_dev_id_t *v);
size_t retrieve_dev_tgt(const char *src, pi_dev_tgt_t *v);
size_t retrieve_status(const char *src, pi_status_t *v);
size_t retrieve_session_handle(const char *src, pi_session_handle_t *v);

#ifdef __cplusplus
}
#endif

#endif  // PI_INT_SERIALIZE_H_
