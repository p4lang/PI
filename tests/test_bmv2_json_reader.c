/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

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

TEST_GROUP_RUNNER(ReadAndSerialize) {
  RUN_TEST_CASE(ReadAndSerialize, SimpleRouter);
  RUN_TEST_CASE(ReadAndSerialize, Valid);
  RUN_TEST_CASE(ReadAndSerialize, Ecmp);
  RUN_TEST_CASE(ReadAndSerialize, Stats);
  RUN_TEST_CASE(ReadAndSerialize, L2Switch);
}

void test_bmv2_json_reader() {
  RUN_TEST_GROUP(SimpleRouter);
  RUN_TEST_GROUP(ReadAndSerialize);
}
