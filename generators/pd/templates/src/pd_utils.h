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

#ifndef _P4_PD_UTILS_H_
#define _P4_PD_UTILS_H_

#include ${target_common_h}

#include <PI/pi.h>
#include <PI/pi_meter.h>

static inline pi_dev_tgt_t convert_dev_tgt(p4_pd_dev_target_t pd_dev_tgt) {
  pi_dev_tgt_t pi_dev_tgt;
  pi_dev_tgt.dev_id = pd_dev_tgt.device_id;
  pi_dev_tgt.dev_pipe_mask = pd_dev_tgt.dev_pipe_id;
  return pi_dev_tgt;
}

void pd_to_pi_bytes_meter_spec(const p4_pd_bytes_meter_spec_t *meter_spec,
                               pi_meter_spec_t *pi_meter_spec);

void pd_to_pi_packets_meter_spec(const p4_pd_packets_meter_spec_t *meter_spec,
                                 pi_meter_spec_t *pi_meter_spec);

#endif
