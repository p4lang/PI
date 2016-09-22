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
