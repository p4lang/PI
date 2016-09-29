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

#include "pd_utils.h"

void pd_to_pi_bytes_meter_spec(const p4_pd_bytes_meter_spec_t *meter_spec,
                               pi_meter_spec_t *pi_meter_spec) {
  pi_meter_spec->meter_unit = PI_METER_UNIT_BYTES;

  // kbits per sec to bytes per sec
  pi_meter_spec->cir = meter_spec->cir_kbps * 1000 / 8;
  // kbits to bytes
  pi_meter_spec->cburst = meter_spec->cburst_kbits * 1000 / 8;

  pi_meter_spec->pir = meter_spec->pir_kbps * 1000 / 8;
  pi_meter_spec->pburst = meter_spec->pburst_kbits * 1000 / 8;

  switch (meter_spec->meter_type) {
    case PD_METER_TYPE_COLOR_AWARE:
      pi_meter_spec->meter_type = PI_METER_TYPE_COLOR_AWARE;
      break;
    case PD_METER_TYPE_COLOR_UNAWARE:
      pi_meter_spec->meter_type = PI_METER_TYPE_COLOR_UNAWARE;
      break;
  }
}

void pd_to_pi_packets_meter_spec(const p4_pd_packets_meter_spec_t *meter_spec,
                                 pi_meter_spec_t *pi_meter_spec) {
  pi_meter_spec->meter_unit = PI_METER_UNIT_PACKETS;

  pi_meter_spec->cir = meter_spec->cir_pps;
  pi_meter_spec->cburst = meter_spec->cburst_pkts;

  pi_meter_spec->pir = meter_spec->pir_pps;
  pi_meter_spec->pburst = meter_spec->pburst_pkts;

  switch (meter_spec->meter_type) {
    case PD_METER_TYPE_COLOR_AWARE:
      pi_meter_spec->meter_type = PI_METER_TYPE_COLOR_AWARE;
      break;
    case PD_METER_TYPE_COLOR_UNAWARE:
      pi_meter_spec->meter_type = PI_METER_TYPE_COLOR_UNAWARE;
      break;
  }
}
