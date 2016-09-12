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

#include "unity/unity_fixture.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void test_bmv2_json_reader();
extern void test_getnetv();
extern void test_p4info();
extern void test_frontends_generic();

static void run() {
#ifdef TEST_BMV2_JSON_READER
  test_bmv2_json_reader();
#endif
#ifdef TEST_GETNETV
  test_getnetv();
#endif
#ifdef TEST_P4INFO
  test_p4info();
#endif
#ifdef TEST_FRONTENDS_GENERIC
  test_frontends_generic();
#endif
}

int main(int argc, const char *argv[]) {
  unsigned int seed = (unsigned int)time(NULL);
  // TODO(antonin): do something more robust, maybe with getopt
  for (int i = 0; i < argc; i++) {
    if (strcmp(argv[i], "--seed") == 0) {
      seed = (unsigned int)atoi(argv[++i]);
    }
  }
  printf("Using seed %u for tests\n", seed);
  srand(seed);
  return UnityMain(argc, argv, run);
}
