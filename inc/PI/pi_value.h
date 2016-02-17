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

#ifndef PI_INC_PI_PI_VALUE_H_
#define PI_INC_PI_PI_VALUE_H_

typedef enum {
  PI_VALUE_TYPE_U8,
  PI_VALUE_TYPE_U16,
  PI_VALUE_TYPE_U32,
  PI_VALUE_TYPE_U64,
  PI_VALUE_TYPE_UPTR,
} pi_value_type_t;

/* 64 bit option can be disabled for 32-bit architecture */
/* implementation can be hidden from user */
/* integers in this struct are stored in network-byte order */
typedef struct {
  uint32_t type_and_size;  // first byte is type, rest is size
  union {
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    char *ptr;
  } value;
} pi_value_t;

void pi_build_value_u8(const uint8_t u8, pi_value_t *value);
void pi_build_value_u16(const uint16_t u16, pi_value_t *value);
void pi_build_value_u32(const uint32_t u32, pi_value_t *value);
void pi_build_value_u64(const uint64_t u64, pi_value_t *value);

// we borrow the pointer, client is still responsible for deleting memory when
// he is done with the value
void pi_build_value_ptr(const char *ptr, uint32_t size, pi_value_t *value);

#endif  // PI_INC_PI_PI_VALUE_H_
