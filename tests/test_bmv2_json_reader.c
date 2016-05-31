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

#include "PI/pi.h"
#include "PI/pi_p4info.h"
#include "utils/utils.h"

#include <assert.h>
#include <stdlib.h>

#include "unity/unity_fixture.h"

#ifndef TESTDATADIR
#define TESTDATADIR "testdata"
#endif

static char *read_json(const char *path) {
  return read_file(path);
}

TEST_GROUP(SimpleRouter);

TEST_SETUP(SimpleRouter) {
  pi_init(256);  // 256 max devices
}

TEST_TEAR_DOWN(SimpleRouter) {
  pi_destroy();
}

TEST(SimpleRouter, Base) {
  pi_p4info_t *p4info;
  char *config = read_json(TESTDATADIR "/" "simple_router.json");
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS,
                    pi_add_config(config, PI_CONFIG_TYPE_BMV2_JSON, &p4info));
  TEST_ASSERT_EQUAL_UINT(4u, pi_p4info_action_get_num(p4info));
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy_config(p4info));
  // FIXME(antonin)
#undef free  // unity weirdness
  free(config);
}

TEST_GROUP_RUNNER(SimpleRouter) {
  RUN_TEST_CASE(SimpleRouter, Base);
}

void test_bmv2_json_reader() {
  RUN_TEST_GROUP(SimpleRouter);
}
