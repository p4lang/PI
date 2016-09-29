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
