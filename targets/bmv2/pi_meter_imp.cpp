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

#include <PI/p4info.h>
#include <PI/pi.h>
#include <PI/target/pi_meter_imp.h>

#include <iostream>
#include <string>
#include <vector>

#include "common.h"
#include "conn_mgr.h"
#include "direct_res_spec.h"

namespace pibmv2 {

extern conn_mgr_t *conn_mgr_state;

}  // namespace pibmv2

namespace {

void
convert_to_meter_spec(const pi_p4info_t *p4info, pi_p4_id_t m_id,
                      pi_meter_spec_t *meter_spec,
                      const std::vector<BmMeterRateConfig> &rates) {
  auto conv_packets = [](const BmMeterRateConfig &rate,
                         uint64_t *r, uint32_t *b) {
    *r = static_cast<uint64_t>(rate.units_per_micros * 1000000.);
    *b = rate.burst_size;
  };
  auto conv_bytes = [](const BmMeterRateConfig &rate,
                       uint64_t *r, uint32_t *b) {
    *r = static_cast<uint64_t>(rate.units_per_micros * 1000000.);
    *b = rate.burst_size;
  };
  meter_spec->meter_unit = static_cast<pi_meter_unit_t>(
      pi_p4info_meter_get_unit(p4info, m_id));
  meter_spec->meter_type = static_cast<pi_meter_type_t>(
      pi_p4info_meter_get_type(p4info, m_id));
  assert(meter_spec->meter_unit != PI_METER_UNIT_DEFAULT);
  // choose appropriate conversion routine
  auto conv = (meter_spec->meter_unit == PI_METER_UNIT_PACKETS) ?
      conv_packets : conv_bytes;
  conv(rates.at(0), &meter_spec->cir, &meter_spec->cburst);
  conv(rates.at(1), &meter_spec->pir, &meter_spec->pburst);
}

std::string get_direct_t_name(const pi_p4info_t *p4info, pi_p4_id_t m_id) {
  pi_p4_id_t t_id = pi_p4info_meter_get_direct(p4info, m_id);
  // guaranteed by PI common code
  assert(t_id != PI_INVALID_ID);
  return std::string(pi_p4info_table_name_from_id(p4info, t_id));
}

}  // namespace

extern "C" {

pi_status_t _pi_meter_read(pi_session_handle_t session_handle,
                           pi_dev_tgt_t dev_tgt,
                           pi_p4_id_t meter_id,
                           size_t index,
                           pi_meter_spec_t *meter_spec) {
  (void)session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string m_name(pi_p4info_meter_name_from_id(p4info, meter_id));

  std::vector<BmMeterRateConfig> rates;
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    client.c->bm_meter_get_rates(rates, 0, m_name, index);
  } catch(InvalidMeterOperation &imo) {
    const char *what =
        _MeterOperationErrorCode_VALUES_TO_NAMES.find(imo.code)->second;
    std::cout << "Invalid meter (" << m_name << ") operation ("
              << imo.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + imo.code);
  }
  if (rates.empty()) return PI_STATUS_METER_SPEC_NOT_SET;
  convert_to_meter_spec(p4info, meter_id, meter_spec, rates);

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_meter_set(pi_session_handle_t session_handle,
                          pi_dev_tgt_t dev_tgt,
                          pi_p4_id_t meter_id,
                          size_t index,
                          const pi_meter_spec_t *meter_spec) {
  (void)session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string m_name(pi_p4info_meter_name_from_id(p4info, meter_id));

  auto rates = pibmv2::convert_from_meter_spec(meter_spec);
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    client.c->bm_meter_set_rates(0, m_name, index, rates);
  } catch(InvalidMeterOperation &imo) {
    const char *what =
        _MeterOperationErrorCode_VALUES_TO_NAMES.find(imo.code)->second;
    std::cout << "Invalid meter (" << m_name << ") operation ("
              << imo.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + imo.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_meter_read_direct(pi_session_handle_t session_handle,
                                  pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                  pi_entry_handle_t entry_handle,
                                  pi_meter_spec_t *meter_spec) {
  (void)session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string t_name = get_direct_t_name(p4info, meter_id);

  std::vector<BmMeterRateConfig> rates;
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    client.c->bm_mt_get_meter_rates(rates, 0, t_name, entry_handle);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }
  if (rates.empty()) return PI_STATUS_METER_SPEC_NOT_SET;
  convert_to_meter_spec(p4info, meter_id, meter_spec, rates);

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_meter_set_direct(pi_session_handle_t session_handle,
                                 pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                 pi_entry_handle_t entry_handle,
                                 const pi_meter_spec_t *meter_spec) {
  (void)session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string t_name = get_direct_t_name(p4info, meter_id);

  auto rates = pibmv2::convert_from_meter_spec(meter_spec);
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    client.c->bm_mt_set_meter_rates(0, t_name, entry_handle, rates);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

}
