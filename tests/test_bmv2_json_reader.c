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

#include "PI/pi.h"
#include "PI/p4info.h"
#include "read_file.h"

#include "utils.h"

#include <assert.h>
#include <stdlib.h>

#include "unity/unity_fixture.h"

#ifndef TESTDATADIR
#define TESTDATADIR "testdata"
#endif

static char *read_json(const char *path) { return read_file(path); }

TEST_GROUP(SimpleRouter);

TEST_SETUP(SimpleRouter) {
  pi_init(256, NULL);  // 256 max devices
}

TEST_TEAR_DOWN(SimpleRouter) { pi_destroy(); }

TEST(SimpleRouter, Base) {
  pi_p4info_t *p4info;
  char *config = read_json(TESTDATADIR
                           "/"
                           "simple_router.json");
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS,
                    pi_add_config(config, PI_CONFIG_TYPE_BMV2_JSON, &p4info));
  TEST_ASSERT_EQUAL_UINT(4u, pi_p4info_action_get_num(p4info));
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy_config(p4info));
  free(config);
}

TEST_GROUP_RUNNER(SimpleRouter) { RUN_TEST_CASE(SimpleRouter, Base); }

TEST_GROUP(ReadAndSerialize);

TEST_SETUP(ReadAndSerialize) { pi_init(256, NULL); }

TEST_TEAR_DOWN(ReadAndSerialize) { pi_destroy(); }

static void read_and_serialize(const char *path) {
  pi_p4info_t *p4info;
  char *config = read_file(path);
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS,
                    pi_add_config(config, PI_CONFIG_TYPE_BMV2_JSON, &p4info));

  char *dump = pi_serialize_config(p4info, 0);
  TEST_ASSERT_NOT_NULL(dump);

  pi_p4info_t *p4info_new;
  TEST_ASSERT_EQUAL(
      PI_STATUS_SUCCESS,
      pi_add_config(dump, PI_CONFIG_TYPE_NATIVE_JSON, &p4info_new));

  char *dump_new = pi_serialize_config(p4info_new, 0);
  TEST_ASSERT_NOT_NULL(dump_new);

  TEST_ASSERT_TRUE(cmp_cJSON(dump, dump_new));

  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy_config(p4info));
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy_config(p4info_new));
  free(dump);
  free(dump_new);
  free(config);
}

TEST(ReadAndSerialize, SimpleRouter) {
  read_and_serialize(TESTDATADIR
                     "/"
                     "simple_router.json");
}

TEST(ReadAndSerialize, Valid) {
  read_and_serialize(TESTDATADIR
                     "/"
                     "valid.json");
}

TEST(ReadAndSerialize, Ecmp) {
  read_and_serialize(TESTDATADIR
                     "/"
                     "ecmp.json");
}

TEST(ReadAndSerialize, Stats) {
  read_and_serialize(TESTDATADIR
                     "/"
                     "stats.json");
}

TEST(ReadAndSerialize, L2Switch) {
  read_and_serialize(TESTDATADIR
                     "/"
                     "l2_switch.json");
}

TEST(ReadAndSerialize, Pragmas) {
  read_and_serialize(TESTDATADIR
                     "/"
                     "pragmas.json");
}

TEST_GROUP_RUNNER(ReadAndSerialize) {
  RUN_TEST_CASE(ReadAndSerialize, SimpleRouter);
  RUN_TEST_CASE(ReadAndSerialize, Valid);
  RUN_TEST_CASE(ReadAndSerialize, Ecmp);
  RUN_TEST_CASE(ReadAndSerialize, Stats);
  RUN_TEST_CASE(ReadAndSerialize, L2Switch);
  RUN_TEST_CASE(ReadAndSerialize, Pragmas);
}

void test_bmv2_json_reader() {
  RUN_TEST_GROUP(SimpleRouter);
  RUN_TEST_GROUP(ReadAndSerialize);
}
