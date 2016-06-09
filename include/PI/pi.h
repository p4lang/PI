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

#ifndef PI_INC_PI_PI_H_
#define PI_INC_PI_PI_H_

#include "pi_base.h"
#include "pi_tables.h"

#ifdef __cplusplus
extern "C" {
#endif

pi_status_t pi_init(size_t max_devices);

typedef struct {
  int end_of_extras;
  const char *key;
  const char *v;
} pi_assign_extra_t;

pi_status_t pi_assign_device(uint16_t dev_id, const pi_p4info_t *p4info,
                             pi_assign_extra_t *extra);

pi_status_t pi_remove_device(uint16_t dev_id);

pi_status_t pi_destroy();

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_H_
