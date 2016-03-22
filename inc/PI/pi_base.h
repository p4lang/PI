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

#ifndef PI_INC_PI_PI_BASE_H_
#define PI_INC_PI_PI_BASE_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
  PI_STATUS_SUCCESS,
  PI_STATUS_CONFIG_READER_ERROR
} pi_status_t;

typedef uint32_t pi_p4_id_t;

typedef struct {
  uint16_t dev_id;
  uint16_t dev_pipe_mask;
} pi_dev_tgt_t;

typedef struct pi_p4info_s pi_p4info_t;

#endif  // PI_INC_PI_PI_BASE_H_
