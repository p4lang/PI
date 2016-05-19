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

#include <stdio.h>

pi_status_t _pi_init() {
  printf("_pi_init\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_assign_device(uint16_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra) {
  (void) dev_id; (void) p4info, (void) extra;
  printf("_pi_assign_device\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_remove_device(uint16_t dev_id) {
  (void) dev_id;
  printf("_pi_remove_device\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_destroy() {
  printf("_pi_destroy\n");
  return PI_STATUS_SUCCESS;
}
