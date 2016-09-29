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

#include <vector>

#include "direct_res_spec.h"

namespace pibmv2 {

BmCounterValue convert_from_counter_data(const pi_counter_data_t *from) {
  BmCounterValue to;
  if (from->valid & PI_COUNTER_UNIT_BYTES)
    to.bytes = static_cast<int64_t>(from->bytes);
  else
    to.bytes = 0;
  if (from->valid & PI_COUNTER_UNIT_PACKETS)
    to.packets = static_cast<int64_t>(from->packets);
  else
    to.packets = 0;
  return to;
}

std::vector<BmMeterRateConfig>
convert_from_meter_spec(const pi_meter_spec_t *meter_spec) {
  std::vector<BmMeterRateConfig> rates;
  auto conv_packets = [](uint64_t r, uint32_t b) {
    BmMeterRateConfig new_rate;
    new_rate.units_per_micros = static_cast<double>(r) / 1000000.;
    new_rate.burst_size = b;
    return new_rate;
  };
  auto conv_bytes = [](uint64_t r, uint32_t b) {
    BmMeterRateConfig new_rate;
    new_rate.units_per_micros = static_cast<double>(r) / 1000000.;
    new_rate.burst_size = b;
    return new_rate;
  };
  // guaranteed by PI common code
  assert(meter_spec->meter_unit != PI_METER_UNIT_DEFAULT);
  // choose appropriate conversion routine
  auto conv = (meter_spec->meter_unit == PI_METER_UNIT_PACKETS) ?
      conv_packets : conv_bytes;
  // perform conversion
  rates.push_back(conv(meter_spec->cir, meter_spec->cburst));
  rates.push_back(conv(meter_spec->pir, meter_spec->pburst));
  return rates;
}

}  // namespace pibmv2
