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

#include <PI/pi_p4info.h>

#include <assert.h>
#include <string.h>

#include <arpa/inet.h>

typedef enum {
  PI_VALUE_TYPE_U8 = 0,
  PI_VALUE_TYPE_U16,
  PI_VALUE_TYPE_U32,
  PI_VALUE_TYPE_U64,
  PI_VALUE_TYPE_PTR,
} pi_value_type_t;

/* 64 bit option can be disabled for 32-bit architecture */
/* implementation can be hidden from user */
typedef struct {
  uint32_t type_and_size;  // first byte is type, rest is size
  union {
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    const char *ptr;
  } value;
} pi_value_t;

inline void pi_getv_u8(const uint8_t u8, pi_value_t *v) {
  v->type_and_size = ((uint8_t) PI_VALUE_TYPE_U8) << 24;
  v->value.u8 = u8;
}

inline void pi_getv_u16(const uint16_t u16, pi_value_t *v) {
  v->type_and_size = ((uint8_t) PI_VALUE_TYPE_U16) << 24;
  v->value.u16 = u16;
}

inline void pi_getv_u32(const uint32_t u32, pi_value_t *v) {
  v->type_and_size = ((uint8_t) PI_VALUE_TYPE_U32) << 24;
  v->value.u32 = u32;
}

inline void pi_getv_u64(const uint64_t u64, pi_value_t *v) {
  v->type_and_size = ((uint8_t) PI_VALUE_TYPE_U64) << 24;
  v->value.u64 = u64;
}

// we borrow the pointer, client is still responsible for deleting memory when
// he is done with the value
inline void pi_getv_ptr(const char *ptr, uint32_t size, pi_value_t *v) {
  assert(size < (1 << 24));
  v->type_and_size = ((uint8_t) PI_VALUE_TYPE_PTR) << 24;
  v->type_and_size |= size;
  v->value.ptr = ptr;
}

// in byte order
typedef struct {
  int is_ptr;
  pi_p4_id_t fid;
  size_t size;
  union {
    char data[8];
    const char *ptr;
  } v;
} pi_fvalue_t;


// we are masking the extra bits in the first byte
inline pi_status_t pi_getfv_u8(const pi_p4info_t *p4info, pi_p4_id_t fid,
                               uint8_t u8, pi_fvalue_t *fv) {
  size_t bitwidth = pi_p4info_field_bitwidth(p4info, fid);
  char byte0_mask = pi_p4info_field_byte0_mask(p4info, fid);
  if (bitwidth > 8) return PI_STATUS_FVALUE_INVALID_SIZE;
  fv->is_ptr = 0;
  fv->fid = fid;
  fv->size = 1;
  u8 &= byte0_mask;
  memcpy(&fv->v.data[0], &u8, 1);
  return PI_STATUS_SUCCESS;
}

inline pi_status_t pi_getfv_u16(const pi_p4info_t *p4info, pi_p4_id_t fid,
                                uint16_t u16, pi_fvalue_t *fv) {
  size_t bitwidth = pi_p4info_field_bitwidth(p4info, fid);
  char byte0_mask = pi_p4info_field_byte0_mask(p4info, fid);
  if (bitwidth <= 8 || bitwidth > 16) return PI_STATUS_FVALUE_INVALID_SIZE;
  fv->is_ptr = 0;
  fv->fid = fid;
  fv->size = 2;
  u16 = htons(u16);
  char *data = (char *) &u16;
  data[0] &= byte0_mask;
  memcpy(&fv->v.data[0], data, 2);
  return PI_STATUS_SUCCESS;
}

inline pi_status_t pi_getfv_u32(const pi_p4info_t *p4info, pi_p4_id_t fid,
                                uint32_t u32, pi_fvalue_t *fv) {
  size_t bitwidth = pi_p4info_field_bitwidth(p4info, fid);
  char byte0_mask = pi_p4info_field_byte0_mask(p4info, fid);
  if (bitwidth <= 16 || bitwidth > 32) return PI_STATUS_FVALUE_INVALID_SIZE;
  fv->is_ptr = 0;
  fv->fid = fid;
  fv->size = (bitwidth + 7) / 8;
  u32 = htonl(u32);
  char *data = (char *) &u32;
  data += (4 - fv->size);
  data[0] &= byte0_mask;
  memcpy(&fv->v.data[0], data, fv->size);
  return PI_STATUS_SUCCESS;
}

inline uint64_t htonll(uint64_t n) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return n;
#else
  return (((uint64_t)htonl(n)) << 32) + htonl(n >> 32);
#endif
}

inline uint64_t ntohll(uint64_t n) {
#if __BYTE_ORDER__ == __BIG_ENDIAN__
  return n;
#else
  return (((uint64_t)ntohl(n)) << 32) + ntohl(n >> 32);
#endif
}

inline pi_status_t pi_getfv_u64(const pi_p4info_t *p4info, pi_p4_id_t fid,
                                uint64_t u64, pi_fvalue_t *fv) {
  size_t bitwidth = pi_p4info_field_bitwidth(p4info, fid);
  char byte0_mask = pi_p4info_field_byte0_mask(p4info, fid);
  if (bitwidth <= 32 || bitwidth > 64) return PI_STATUS_FVALUE_INVALID_SIZE;
  fv->is_ptr = 0;
  fv->fid = fid;
  fv->size = (bitwidth + 7) / 8;
  u64 = htonll(u64);
  char *data = (char *) &u64;
  data += (8 - fv->size);
  data[0] &= byte0_mask;
  memcpy(&fv->v.data[0], data, fv->size);
  return PI_STATUS_SUCCESS;
}


// we borrow the pointer, client is still responsible for deleting memory when
// he is done with the value
// unlike for previous cases, I am not masking the first byte, because I do not
// want to write to the client's memory
// FIXME(antonin)
inline pi_status_t pi_getfv_ptr(pi_p4info_t *p4info, pi_p4_id_t fid,
                                const char *ptr, size_t size,
                                pi_fvalue_t *fv) {
  size_t bitwidth = pi_p4info_field_bitwidth(p4info, fid);
  if ((bitwidth + 7) / 8 != size) return PI_STATUS_FVALUE_INVALID_SIZE;
  fv->is_ptr = 1;
  fv->fid = fid;
  fv->size = size;
  fv->v.ptr = ptr;
  return PI_STATUS_SUCCESS;
}

#endif  // PI_INC_PI_PI_VALUE_H_
