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

#ifndef PI_SRC_TARGET_PI_IMP_H_
#define PI_SRC_TARGET_PI_IMP_H_

#include "PI/pi.h"

pi_status_t _pi_init();

pi_status_t _pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra);

pi_status_t _pi_remove_device(pi_dev_id_t dev_id);

pi_status_t _pi_destroy();

#endif  // PI_SRC_TARGET_PI_IMP_H_
