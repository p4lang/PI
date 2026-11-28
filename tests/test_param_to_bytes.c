/* Copyright 2013-present Barefoot Networks, Inc.
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

#include "CLI/utils.h"

#include "unity/unity_fixture.h"

#include <string.h>

// CLI/utils.c references this global; normally defined by the CLI frontend
const pi_p4info_t *p4info_curr;

TEST_GROUP(ParamToBytes);

TEST_SETUP(ParamToBytes) {}

TEST_TEAR_DOWN(ParamToBytes) {}

TEST(ParamToBytes, ValidShort) {
  unsigned char out[1] = {0};
  TEST_ASSERT_EQUAL_INT(0, param_to_bytes("ff", (char *)out, 8));
  TEST_ASSERT_EQUAL_HEX8(0xff, out[0]);
}

TEST(ParamToBytes, OddNumberOfDigits) {
  unsigned char out[1] = {0};
  TEST_ASSERT_EQUAL_INT(0, param_to_bytes("f", (char *)out, 8));
  TEST_ASSERT_EQUAL_HEX8(0x0f, out[0]);
}

TEST(ParamToBytes, ZeroXPrefix) {
  unsigned char out[1] = {0};
  TEST_ASSERT_EQUAL_INT(0, param_to_bytes("0x1", (char *)out, 8));
  TEST_ASSERT_EQUAL_HEX8(0x01, out[0]);
  TEST_ASSERT_EQUAL_INT(0, param_to_bytes("0xff", (char *)out, 8));
  TEST_ASSERT_EQUAL_HEX8(0xff, out[0]);
}

TEST(ParamToBytes, ValidZero) {
  unsigned char out[1] = {0xff};
  TEST_ASSERT_EQUAL_INT(0, param_to_bytes("0", (char *)out, 8));
  TEST_ASSERT_EQUAL_HEX8(0x00, out[0]);
  TEST_ASSERT_EQUAL_INT(0, param_to_bytes("0x0", (char *)out, 8));
  TEST_ASSERT_EQUAL_HEX8(0x00, out[0]);
}

// A full-width value must not be truncated: 128 hex digits for a 512-bit field.
TEST(ParamToBytes, FullWidthNotTruncated) {
  char param[129];
  memset(param, 'a', 128);
  param[128] = '\0';
  unsigned char out[64];
  memset(out, 0, sizeof(out));
  TEST_ASSERT_EQUAL_INT(0, param_to_bytes(param, (char *)out, 512));
  unsigned char expected[64];
  memset(expected, 0xaa, sizeof(expected));
  TEST_ASSERT_EQUAL_MEMORY(expected, out, sizeof(out));
}

// Empty string is not a valid number.
TEST(ParamToBytes, EmptyRejected) {
  unsigned char out[1] = {0};
  TEST_ASSERT_EQUAL_INT(1, param_to_bytes("", (char *)out, 8));
}

// Bare "0x" prefix with no digits is not a valid number.
TEST(ParamToBytes, BareZeroXRejected) {
  unsigned char out[16];
  memset(out, 0, sizeof(out));
  TEST_ASSERT_EQUAL_INT(1, param_to_bytes("0x", (char *)out, 8));
  TEST_ASSERT_EQUAL_INT(1, param_to_bytes("0x", (char *)out, 32));
  TEST_ASSERT_EQUAL_INT(1, param_to_bytes("0x", (char *)out, 48));
  TEST_ASSERT_EQUAL_INT(1, param_to_bytes("0x", (char *)out, 128));
}

// Inputs longer than the internal copy must be rejected, not truncated.
TEST(ParamToBytes, OverlongRejected) {
  unsigned char out[64];
  memset(out, 0, sizeof(out));

  // 8-bit field: 3 hex digits is already too long
  TEST_ASSERT_EQUAL_INT(1, param_to_bytes("fff", (char *)out, 8));

  // 512-bit field (64 bytes, max 128 hex digits)
  char param[256];

  // one extra digit past full width
  memset(param, 'a', 129);
  param[129] = '\0';
  TEST_ASSERT_EQUAL_INT(1, param_to_bytes(param, (char *)out, 512));

  // invalid character past any truncation point
  memset(param, 'a', 128);
  param[128] = 'x';
  param[129] = '\0';
  TEST_ASSERT_EQUAL_INT(1, param_to_bytes(param, (char *)out, 512));

  // far over the limit
  memset(param, 'a', 200);
  param[200] = '\0';
  TEST_ASSERT_EQUAL_INT(1, param_to_bytes(param, (char *)out, 512));
}

TEST_GROUP_RUNNER(ParamToBytes) {
  RUN_TEST_CASE(ParamToBytes, ValidShort);
  RUN_TEST_CASE(ParamToBytes, OddNumberOfDigits);
  RUN_TEST_CASE(ParamToBytes, ZeroXPrefix);
  RUN_TEST_CASE(ParamToBytes, ValidZero);
  RUN_TEST_CASE(ParamToBytes, FullWidthNotTruncated);
  RUN_TEST_CASE(ParamToBytes, EmptyRejected);
  RUN_TEST_CASE(ParamToBytes, BareZeroXRejected);
  RUN_TEST_CASE(ParamToBytes, OverlongRejected);
}

void test_param_to_bytes() { RUN_TEST_GROUP(ParamToBytes); }
