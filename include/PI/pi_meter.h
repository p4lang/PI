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

#ifndef PI_INC_PI_PI_METER_H_
#define PI_INC_PI_PI_METER_H_

#include <PI/pi_base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  PI_METER_UNIT_DEFAULT,  // as per the P4 program?
  PI_METER_UNIT_PACKETS,
  PI_METER_UNIT_BYTES,
} pi_meter_unit_t;

typedef enum {
  PI_METER_TYPE_COLOR_DEFAULT,  // as per the P4 program?
  PI_METER_TYPE_COLOR_AWARE,
  PI_METER_TYPE_COLOR_UNAWARE
} pi_meter_type_t;

typedef struct {
  uint32_t cir;
  uint32_t cburst;
  uint32_t pir;
  uint32_t pburst;
  pi_meter_unit_t meter_unit;
  pi_meter_type_t meter_type;
} pi_meter_spec_t;

pi_status_t pi_meter_read(pi_session_handle_t session_handle,
                          pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                          size_t index, pi_meter_spec_t *meter_spec);

pi_status_t pi_meter_set(pi_session_handle_t session_handle,
                         pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                         size_t index, const pi_meter_spec_t *meter_spec);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_METER_H_
