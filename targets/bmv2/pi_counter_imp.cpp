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
#include <PI/target/pi_counter_imp.h>

#include <iostream>
#include <string>
#include <thread>

#include "common.h"
#include "conn_mgr.h"
#include "direct_res_spec.h"

namespace pibmv2 {

extern conn_mgr_t *conn_mgr_state;

}  // namespace pibmv2

namespace {

void convert_to_counter_data(pi_counter_data_t *to,
                             const BmCounterValue &from) {
  // with bmv2, both are always valid
  to->valid = PI_COUNTER_UNIT_PACKETS | PI_COUNTER_UNIT_BYTES;
  to->bytes = static_cast<pi_counter_value_t>(from.bytes);
  to->packets = static_cast<pi_counter_value_t>(from.packets);
}

bool are_both_values_set(const pi_counter_data_t *counter_data) {
  return (counter_data->valid & PI_COUNTER_UNIT_BYTES) &&
      (counter_data->valid & PI_COUNTER_UNIT_PACKETS);
}

void merge_current_value(pi_counter_data_t *desired_data,
                         const pi_counter_data_t *curr_data) {
  if (!(desired_data->valid & PI_COUNTER_UNIT_BYTES)) {
    assert(curr_data->valid & PI_COUNTER_UNIT_BYTES);
    desired_data->valid |= PI_COUNTER_UNIT_BYTES;
    desired_data->bytes = curr_data->bytes;
  }
  if (!(desired_data->valid & PI_COUNTER_UNIT_PACKETS)) {
    assert(curr_data->valid & PI_COUNTER_UNIT_PACKETS);
    desired_data->valid |= PI_COUNTER_UNIT_PACKETS;
    desired_data->packets = curr_data->packets;
  }
}

std::string get_direct_t_name(const pi_p4info_t *p4info, pi_p4_id_t c_id) {
  pi_p4_id_t t_id = pi_p4info_counter_get_direct(p4info, c_id);
  // guaranteed by PI common code
  assert(t_id != PI_INVALID_ID);
  return std::string(pi_p4info_table_name_from_id(p4info, t_id));
}

}  // namespace

extern "C" {

pi_status_t _pi_counter_read(pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                             size_t index, int flags,
                             pi_counter_data_t *counter_data) {
  (void)session_handle;
  (void)flags;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string c_name(pi_p4info_counter_name_from_id(p4info, counter_id));

  BmCounterValue value;
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    client.c->bm_counter_read(value, 0, c_name, index);
  } catch(InvalidCounterOperation &ico) {
    const char *what =
        _CounterOperationErrorCode_VALUES_TO_NAMES.find(ico.code)->second;
    std::cout << "Invalid counter (" << c_name << ") operation ("
              << ico.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ico.code);
  }

  convert_to_counter_data(counter_data, value);

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_counter_write(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                              size_t index,
                              const pi_counter_data_t *counter_data) {
  (void)session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string c_name(pi_p4info_counter_name_from_id(p4info, counter_id));

  // very poor man solution: bmv2 does not (yet) let us set only one of bytes /
  // packets, so we first retrieve the current data and use it
  pi_counter_data_t desired_data = *counter_data;
  if (!are_both_values_set(counter_data)) {
    pi_counter_data_t curr_data;
    pi_status_t status = _pi_counter_read(session_handle, dev_tgt,
                                          counter_id, index, 0, &curr_data);
    if (status != PI_STATUS_SUCCESS) return status;
    merge_current_value(&desired_data, &curr_data);
  }

  BmCounterValue value = pibmv2::convert_from_counter_data(&desired_data);
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    client.c->bm_counter_write(0, c_name, index, value);
  } catch(InvalidCounterOperation &ico) {
    const char *what =
        _CounterOperationErrorCode_VALUES_TO_NAMES.find(ico.code)->second;
    std::cout << "Invalid counter (" << c_name << ") operation ("
              << ico.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ico.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_counter_read_direct(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                    pi_entry_handle_t entry_handle, int flags,
                                    pi_counter_data_t *counter_data) {
  (void)session_handle;
  (void)flags;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string t_name = get_direct_t_name(p4info, counter_id);

  BmCounterValue value;
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    client.c->bm_mt_read_counter(value, 0, t_name, entry_handle);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  convert_to_counter_data(counter_data, value);

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_counter_write_direct(pi_session_handle_t session_handle,
                                     pi_dev_tgt_t dev_tgt,
                                     pi_p4_id_t counter_id,
                                     pi_entry_handle_t entry_handle,
                                     const pi_counter_data_t *counter_data) {
  (void)session_handle;

  pibmv2::device_info_t *d_info = pibmv2::get_device_info(dev_tgt.dev_id);
  assert(d_info->assigned);
  const pi_p4info_t *p4info = d_info->p4info;
  std::string t_name = get_direct_t_name(p4info, counter_id);

  // very poor man solution: bmv2 does not (yet) let us set only one of bytes /
  // packets, so we first retrieve the current data and use it
  pi_counter_data_t desired_data = *counter_data;
  if (!are_both_values_set(counter_data)) {
    pi_counter_data_t curr_data;
    pi_status_t status = _pi_counter_read_direct(session_handle, dev_tgt,
                                                 counter_id, entry_handle, 0,
                                                 &curr_data);
    if (status != PI_STATUS_SUCCESS) return status;
    merge_current_value(&desired_data, &curr_data);
  }

  BmCounterValue value = pibmv2::convert_from_counter_data(&desired_data);
  auto client = conn_mgr_client(pibmv2::conn_mgr_state, dev_tgt.dev_id);
  try {
    client.c->bm_mt_write_counter(0, t_name, entry_handle, value);
  } catch (InvalidTableOperation &ito) {
    const char *what =
        _TableOperationErrorCode_VALUES_TO_NAMES.find(ito.code)->second;
    std::cout << "Invalid table (" << t_name << ") operation ("
              << ito.code << "): " << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + ito.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_counter_hw_sync(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                PICounterHwSyncCb cb, void *cb_cookie) {
  (void)session_handle;
  if (!cb) return PI_STATUS_SUCCESS;
  std::thread cb_thread(cb, dev_tgt.dev_id, counter_id, cb_cookie);
  cb_thread.detach();
  return PI_STATUS_SUCCESS;
}

}
