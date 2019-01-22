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

#include "PI/pi_value.h"
#include "p4info/p4info_struct.h"
#include "p4info/tables_int.h"
#include "utils/utils.h"

#include "unity/unity_fixture.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static pi_p4info_t *p4info;
static pi_p4_id_t tid;

TEST_GROUP(GetNetv);

TEST_SETUP(GetNetv) {
  pi_add_config(NULL, PI_CONFIG_TYPE_NONE, &p4info);
  pi_p4info_table_init(p4info, 1);
  tid = pi_make_table_id(0);
  const size_t num_mfs = 256;
  pi_p4info_table_add(p4info, tid, "t", num_mfs, 0, 1, false, false);
  for (size_t i = 0; i < num_mfs; i++) {
    char name[16];
    snprintf(name, sizeof(name), "f%zu", i);
    pi_p4info_table_add_match_field(p4info, tid, i, name,
                                    PI_P4INFO_MATCH_TYPE_EXACT, i + 1);
  }
}

TEST_TEAR_DOWN(GetNetv) { pi_destroy_config(p4info); }

static char get_byte0_mask(size_t bitwidth) {
  if (bitwidth % 8 == 0) return 0xff;
  int nbits = bitwidth % 8;
  return ((1 << nbits) - 1);
}

TEST(GetNetv, U8) {
  pi_status_t rc;
  for (size_t bitwidth = 1; bitwidth <= 8; bitwidth++) {
    for (uint32_t v = 0; v < (uint32_t)(1 << bitwidth); v++) {
      uint8_t test_v = v;
      pi_netv_t fv;
      pi_p4_id_t fid = bitwidth - 1;
      rc = pi_getnetv_u8(p4info, tid, fid, test_v, &fv);
      TEST_ASSERT_EQUAL_INT(PI_STATUS_SUCCESS, rc);
      // test internals
      TEST_ASSERT_FALSE(fv.is_ptr);
      TEST_ASSERT_EQUAL_UINT(fid, fv.obj_id);
      TEST_ASSERT_EQUAL_UINT(1, fv.size);
      TEST_ASSERT_EQUAL_MEMORY(&test_v, fv.v.data, fv.size);
    }
  }
}

TEST(GetNetv, U8_ExtraBits) {
  pi_status_t rc;
  for (size_t bitwidth = 1; bitwidth <= 8; bitwidth++) {
    for (uint32_t v = (uint32_t)(1 << bitwidth) - 1; v < 256; v++) {
      uint8_t test_v = v;
      pi_netv_t fv;
      pi_p4_id_t fid = bitwidth - 1;
      rc = pi_getnetv_u8(p4info, tid, fid, test_v, &fv);
      TEST_ASSERT_EQUAL_INT(PI_STATUS_SUCCESS, rc);
      test_v &= get_byte0_mask(bitwidth);
      TEST_ASSERT_EQUAL_MEMORY(&test_v, fv.v.data, fv.size);
    }
  }
}

TEST(GetNetv, U8_BadInput) {
  pi_status_t rc;
  uint8_t test_v = 0;
  pi_netv_t fv;
  pi_p4_id_t fid_too_wide = 9 - 1;
  rc = pi_getnetv_u8(p4info, tid, fid_too_wide, test_v, &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_NETV_INVALID_SIZE, rc);
}

TEST(GetNetv, U16) {
  pi_status_t rc;
  for (size_t bitwidth = 9; bitwidth <= 16; bitwidth++) {
    for (uint32_t v = 0; v < (uint32_t)(1 << bitwidth); v++) {
      uint16_t test_v = v;
      pi_netv_t fv;
      pi_p4_id_t fid = bitwidth - 1;
      rc = pi_getnetv_u16(p4info, tid, fid, test_v, &fv);
      TEST_ASSERT_EQUAL_INT(PI_STATUS_SUCCESS, rc);
      // test internals
      TEST_ASSERT_FALSE(fv.is_ptr);
      TEST_ASSERT_EQUAL_UINT(fid, fv.obj_id);
      TEST_ASSERT_EQUAL_UINT(2, fv.size);
      test_v = htons(test_v);
      char *test_v_ = (char *)&test_v;
      TEST_ASSERT_EQUAL_MEMORY(test_v_, fv.v.data, fv.size);
    }
  }
}

TEST(GetNetv, U16_BadInput) {
  pi_status_t rc;
  uint16_t test_v = 0;
  pi_netv_t fv;
  pi_p4_id_t fid_too_wide = 17 - 1;
  rc = pi_getnetv_u16(p4info, tid, fid_too_wide, test_v, &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_NETV_INVALID_SIZE, rc);
  // whether this is an error is still up for debate
  pi_p4_id_t fid_too_narrow = 8 - 1;
  rc = pi_getnetv_u16(p4info, tid, fid_too_narrow, test_v, &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_NETV_INVALID_SIZE, rc);
}

static uint32_t get_rand_u32() {
  uint32_t res;
  char *res_ = (char *)&res;
  for (size_t i = 0; i < sizeof(res); i++) res_[i] = rand() % 256;
  return res;
}

TEST(GetNetv, U32) {
  pi_status_t rc;
  for (size_t bitwidth = 17; bitwidth <= 32; bitwidth++) {
    uint32_t test_v = get_rand_u32();
    pi_netv_t fv;
    pi_p4_id_t fid = bitwidth - 1;
    rc = pi_getnetv_u32(p4info, tid, fid, test_v, &fv);
    TEST_ASSERT_EQUAL_INT(PI_STATUS_SUCCESS, rc);
    TEST_ASSERT_FALSE(fv.is_ptr);
    TEST_ASSERT_EQUAL_UINT(fid, fv.obj_id);
    TEST_ASSERT_EQUAL_UINT((bitwidth + 7) / 8, fv.size);
    test_v = htonl(test_v);
    char *test_v_ = (char *)&test_v;
    if (bitwidth <= 24) test_v_++;
    test_v_[0] &= get_byte0_mask(bitwidth);
    TEST_ASSERT_EQUAL_MEMORY(test_v_, fv.v.data, fv.size);
  }
}

TEST(GetNetv, U32_BadInput) {
  pi_status_t rc;
  uint32_t test_v = 0;
  pi_netv_t fv;
  pi_p4_id_t fid_too_wide = 33 - 1;
  rc = pi_getnetv_u32(p4info, tid, fid_too_wide, test_v, &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_NETV_INVALID_SIZE, rc);
  // whether this is an error is still up for debate
  pi_p4_id_t fid_too_narrow = 16 - 1;
  rc = pi_getnetv_u32(p4info, tid, fid_too_narrow, test_v, &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_NETV_INVALID_SIZE, rc);
}

static uint32_t get_rand_u64() {
  uint64_t res1 = get_rand_u32();
  uint64_t res2 = get_rand_u32();
  return (res1 << 32) | res2;
}

TEST(GetNetv, U64) {
  pi_status_t rc;
  for (size_t bitwidth = 33; bitwidth <= 64; bitwidth++) {
    uint64_t test_v = get_rand_u64();
    pi_netv_t fv;
    pi_p4_id_t fid = bitwidth - 1;
    rc = pi_getnetv_u64(p4info, tid, fid, test_v, &fv);
    TEST_ASSERT_EQUAL_INT(PI_STATUS_SUCCESS, rc);
    TEST_ASSERT_FALSE(fv.is_ptr);
    TEST_ASSERT_EQUAL_UINT(fid, fv.obj_id);
    TEST_ASSERT_EQUAL_UINT((bitwidth + 7) / 8, fv.size);
    test_v = htonll(test_v);
    char *test_v_ = (char *)&test_v;
    test_v_ += (8 - fv.size);
    test_v_[0] &= get_byte0_mask(bitwidth);
    TEST_ASSERT_EQUAL_MEMORY(test_v_, fv.v.data, fv.size);
  }
}

TEST(GetNetv, U64_BadInput) {
  pi_status_t rc;
  uint64_t test_v = 0;
  pi_netv_t fv;
  pi_p4_id_t fid_too_wide = 65 - 1;
  rc = pi_getnetv_u64(p4info, tid, fid_too_wide, test_v, &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_NETV_INVALID_SIZE, rc);
  // whether this is an error is still up for debate
  pi_p4_id_t fid_too_narrow = 32 - 1;
  rc = pi_getnetv_u64(p4info, tid, fid_too_narrow, test_v, &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_NETV_INVALID_SIZE, rc);
}

TEST(GetNetv, Ptr) {
  pi_status_t rc;
  char test_v[16];
  size_t bitwidth = 8 * sizeof(test_v);
  for (size_t i = 0; i < sizeof(test_v); i++) test_v[i] = rand() % 256;
  pi_netv_t fv;
  pi_p4_id_t fid = bitwidth - 1;
  rc = pi_getnetv_ptr(p4info, tid, fid, test_v, sizeof(test_v), &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_SUCCESS, rc);
  TEST_ASSERT_TRUE(fv.is_ptr);
  TEST_ASSERT_EQUAL_UINT(fid, fv.obj_id);
  TEST_ASSERT_EQUAL_UINT(sizeof(test_v), fv.size);
  TEST_ASSERT_EQUAL_MEMORY(test_v, fv.v.ptr, fv.size);
}

TEST(GetNetv, Ptr_BadInput) {
  pi_status_t rc;
  char test_v[16];
  memset(test_v, 0, sizeof(test_v));
  pi_netv_t fv;
  pi_p4_id_t fid_96 = 96 - 1;
  rc = pi_getnetv_ptr(p4info, tid, fid_96, test_v, sizeof(test_v), &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_NETV_INVALID_SIZE, rc);
}

TEST(GetNetv, BadObjType) {
  pi_status_t rc;
  uint8_t test_v = 0;
  pi_netv_t fv;
  pi_p4_id_t bad_table_id = PI_INVALID_ID;
  rc = pi_getnetv_u8(p4info, bad_table_id, 0, test_v, &fv);
  TEST_ASSERT_EQUAL_INT(PI_STATUS_NETV_INVALID_OBJ_ID, rc);
}

TEST_GROUP_RUNNER(GetNetv) {
  RUN_TEST_CASE(GetNetv, U8);
  RUN_TEST_CASE(GetNetv, U8_ExtraBits);
  RUN_TEST_CASE(GetNetv, U8_BadInput);
  RUN_TEST_CASE(GetNetv, U16);
  RUN_TEST_CASE(GetNetv, U16_BadInput);
  RUN_TEST_CASE(GetNetv, U32);
  RUN_TEST_CASE(GetNetv, U32_BadInput);
  RUN_TEST_CASE(GetNetv, U64);
  RUN_TEST_CASE(GetNetv, U64_BadInput);
  RUN_TEST_CASE(GetNetv, Ptr);
  RUN_TEST_CASE(GetNetv, Ptr_BadInput);
  RUN_TEST_CASE(GetNetv, BadObjType);
}

void test_getnetv() { RUN_TEST_GROUP(GetNetv); }
