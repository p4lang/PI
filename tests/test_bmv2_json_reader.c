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

#include "PI/p4info.h"
#include "PI/pi.h"
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

TEST(ReadAndSerialize, ActProf) {
  read_and_serialize(TESTDATADIR
                     "/"
                     "act_prof.json");
}

TEST_GROUP_RUNNER(ReadAndSerialize) {
  RUN_TEST_CASE(ReadAndSerialize, SimpleRouter);
  RUN_TEST_CASE(ReadAndSerialize, Valid);
  RUN_TEST_CASE(ReadAndSerialize, Ecmp);
  RUN_TEST_CASE(ReadAndSerialize, Stats);
  RUN_TEST_CASE(ReadAndSerialize, L2Switch);
  RUN_TEST_CASE(ReadAndSerialize, Pragmas);
  RUN_TEST_CASE(ReadAndSerialize, ActProf);
}

TEST_GROUP(IdAssignment);

TEST_SETUP(IdAssignment) {
  pi_init(256, NULL);  // 256 max devices
}

TEST_TEAR_DOWN(IdAssignment) { pi_destroy(); }

TEST(IdAssignment, Pragmas) {
  pi_p4info_t *p4info;
  char *config = read_json(TESTDATADIR
                           "/"
                           "pragmas.json");
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS,
                    pi_add_config(config, PI_CONFIG_TYPE_BMV2_JSON, &p4info));

  // the expected ids are taken from pragmas.[p4/json]

  TEST_ASSERT_EQUAL_UINT((PI_METER_ID << 24) | 5,
                         pi_p4info_meter_id_from_name(p4info, "m"));

  TEST_ASSERT_EQUAL_UINT((PI_COUNTER_ID << 24) | 6,
                         pi_p4info_counter_id_from_name(p4info, "c"));

  pi_p4_id_t action_id = (PI_ACTION_ID << 24) | 8;
  TEST_ASSERT_EQUAL_UINT(action_id, pi_p4info_action_id_from_name(p4info, "a"));
  TEST_ASSERT_EQUAL_UINT(
      1, pi_p4info_action_param_id_from_name(p4info, action_id, "ap"));

  TEST_ASSERT_EQUAL_UINT((PI_TABLE_ID << 24) | 9,
                         pi_p4info_table_id_from_name(p4info, "t"));
  TEST_ASSERT_EQUAL_UINT((PI_TABLE_ID << 24) | 10,
                         pi_p4info_table_id_from_name(p4info, "t2"));
  TEST_ASSERT_EQUAL_UINT((PI_ACT_PROF_ID << 24) | 11,
                         pi_p4info_act_prof_id_from_name(p4info, "ap"));

  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy_config(p4info));
  free(config);
}

TEST(IdAssignment, IdCollision) {
  // When we generate 32-bit ids for most resources, the least significant 16
  // bits are determined by hashing the name of the resource. This test verifies
  // that when there's a hash collision, the collision is resolved, and that
  // this is done in such a way that the most significant 16 bits of the id
  // aren't affected.
  pi_p4info_t *p4info;
  char *config = read_json(TESTDATADIR
                           "/"
                           "id_collision.json");
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS,
                    pi_add_config(config, PI_CONFIG_TYPE_BMV2_JSON, &p4info));

  // The checks below rely on the fact that `id_collision.json` contains two
  // actions with names that hash to 0xffff. Note that this means that this test
  // is sensitive to the particular hash function used in
  // generate_id_from_name(). A general test could be implemented using the
  // pigeonhole principle, but it would run so slowly that it's not worth it.
  pi_p4_id_t last_id = PI_INVALID_ID;
  for (pi_p4_id_t id = pi_p4info_action_begin(p4info);
       id != pi_p4info_action_end(p4info);
       id = pi_p4info_action_next(p4info, id)) {
    // The two ids should be different - i.e., the collision should be resolved.
    TEST_ASSERT_NOT_EQUAL(last_id, id);
    last_id = id;

    // The first byte should continue to correctly identify the resource type.
    TEST_ASSERT_TRUE(pi_is_action_id(id));

    // The second byte should be zero.
    TEST_ASSERT_EQUAL(0, (id >> 16) & 0xff);
  }

  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy_config(p4info));
  free(config);
}

TEST_GROUP_RUNNER(IdAssignment) {
  RUN_TEST_CASE(IdAssignment, Pragmas);
  RUN_TEST_CASE(IdAssignment, IdCollision);
}

void test_bmv2_json_reader() {
  RUN_TEST_GROUP(SimpleRouter);
  RUN_TEST_GROUP(ReadAndSerialize);
  RUN_TEST_GROUP(IdAssignment);
}
