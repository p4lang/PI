/* Copyright 2026 Lorenzo Rinieri
 * SPDX-License-Identifier: Apache-2.0
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

#include <PI/p4info.h>
#include <PI/pi.h>
#include <PI/target/pi_register_imp.h>

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>

#include "common.h"
#include "conn_mgr.h"

namespace pibmv2 {

extern conn_mgr_t *conn_mgr_state;

}  // namespace pibmv2

namespace {

// The bmv2 Thrift API represents register values as signed 64-bit integers,
// and bmv2 saturates the values which do not fit when reading them (a 64-bit
// cell holding 2^63 is read as 2^63 - 1), so only cells of up to 63 bits are
// supported.
constexpr size_t kMaxBitwidth = 63;

uint64_t value_from_bytes(const char *value, size_t nbytes) {
  uint64_t v = 0;
  for (size_t i = 0; i < nbytes; i++)
    v = (v << 8) | static_cast<uint8_t>(value[i]);
  return v;
}

void value_to_bytes(uint64_t v, size_t bitwidth, char *value) {
  size_t nbytes = (bitwidth + 7) / 8;
  for (size_t i = nbytes; i > 0; i--) {
    value[i - 1] = static_cast<char>(v & 0xff);
    v >>= 8;
  }
  // bits beyond the bitwidth are not part of the PI representation
  size_t zero_nbits = nbytes * 8 - bitwidth;
  value[0] &= static_cast<char>(0xff >> zero_nbits);
}

pi_status_t print_error(const std::string &r_name,
                        const InvalidRegisterOperation &iro) {
  const char *what =
      _RegisterOperationErrorCode_VALUES_TO_NAMES.find(iro.code)->second;
  std::cout << "Invalid register (" << r_name << ") operation ("
            << iro.code << "): " << what << std::endl;
  return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + iro.code);
}

}  // namespace

extern "C" {

pi_status_t _pi_register_read(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                              size_t index, char *value) {
  (void)session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string r_name(pi_p4info_register_name_from_id(p4info, register_id));
  size_t bitwidth = pi_p4info_register_get_bitwidth(p4info, register_id);
  if (bitwidth > kMaxBitwidth) return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;

  BmRegisterValue v;
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    v = client.c->bm_register_read(0, r_name, index);
  } catch (InvalidRegisterOperation &iro) {
    return print_error(r_name, iro);
  }

  value_to_bytes(static_cast<uint64_t>(v), bitwidth, value);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_register_write(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                               size_t index, const char *value) {
  (void)session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string r_name(pi_p4info_register_name_from_id(p4info, register_id));
  size_t bitwidth = pi_p4info_register_get_bitwidth(p4info, register_id);
  if (bitwidth > kMaxBitwidth) return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;

  auto v = static_cast<BmRegisterValue>(
      value_from_bytes(value, (bitwidth + 7) / 8));
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    client.c->bm_register_write(0, r_name, index, v);
  } catch (InvalidRegisterOperation &iro) {
    return print_error(r_name, iro);
  }

  return PI_STATUS_SUCCESS;
}

}
