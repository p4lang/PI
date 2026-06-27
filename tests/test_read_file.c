/* Copyright 2026-present The P4 Language Consortium & Devansh Singh
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

#include "read_file.h"

#include "unity/unity_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EMPTY_FILE "read_file_empty.tmp"
#define TEXT_FILE "read_file_text.tmp"
#define MISSING_FILE "read_file_missing.tmp"

TEST_GROUP(ReadFile);

TEST_SETUP(ReadFile) {
  remove(EMPTY_FILE);
  remove(TEXT_FILE);
  remove(MISSING_FILE);
}

TEST_TEAR_DOWN(ReadFile) {
  remove(EMPTY_FILE);
  remove(TEXT_FILE);
  remove(MISSING_FILE);
}

TEST(ReadFile, MissingFile) { TEST_ASSERT_NULL(read_file(MISSING_FILE)); }

TEST(ReadFile, EmptyFile) {
  FILE *fp = fopen(EMPTY_FILE, "wb");
  TEST_ASSERT_NOT_NULL(fp);
  TEST_ASSERT_EQUAL_INT(0, fclose(fp));

  char *contents = read_file(EMPTY_FILE);
  TEST_ASSERT_NOT_NULL(contents);
  TEST_ASSERT_EQUAL_STRING("", contents);
  free(contents);
}

TEST(ReadFile, TextFile) {
  const char *expected = "line 1\nline 2\n";
  FILE *fp = fopen(TEXT_FILE, "wb");
  TEST_ASSERT_NOT_NULL(fp);
  TEST_ASSERT_TRUE(fputs(expected, fp) >= 0);
  TEST_ASSERT_EQUAL_INT(0, fclose(fp));

  char *contents = read_file(TEXT_FILE);
  TEST_ASSERT_NOT_NULL(contents);
  TEST_ASSERT_EQUAL_STRING(expected, contents);
  free(contents);
}

TEST_GROUP_RUNNER(ReadFile) {
  RUN_TEST_CASE(ReadFile, MissingFile);
  RUN_TEST_CASE(ReadFile, EmptyFile);
  RUN_TEST_CASE(ReadFile, TextFile);
}

void test_read_file() { RUN_TEST_GROUP(ReadFile); }
