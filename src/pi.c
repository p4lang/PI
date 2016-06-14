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

#include "PI/pi.h"
#include "PI/target/pi_imp.h"
#include "PI/int/pi_int.h"

#include <stdlib.h>

#define MAX_DEVICES 256

static size_t num_devices;
static pi_device_info_t *device_mapping;
static char *rpc_addr_;

pi_device_info_t *pi_get_device_info(uint16_t dev_id) {
  return device_mapping + dev_id;
}

pi_device_info_t *pi_get_devices(size_t *nb) {
  *nb = num_devices;
  return device_mapping;
}

const pi_p4info_t *pi_get_device_p4info(pi_dev_id_t dev_id) {
  return device_mapping[dev_id].p4info;
}

pi_status_t pi_init(size_t max_devices, char *rpc_addr) {
  num_devices = max_devices;
  device_mapping = calloc(max_devices, sizeof(pi_device_info_t));
  rpc_addr_ = rpc_addr;
  return _pi_init((void *) rpc_addr);
}

void pi_update_device_config(pi_dev_id_t dev_id, const pi_p4info_t *p4info) {
  pi_device_info_t *info = &device_mapping[dev_id];
  info->version++;
  info->p4info = p4info;
}

void pi_reset_device_config(pi_dev_id_t dev_id) {
  pi_device_info_t *info = &device_mapping[dev_id];
  info->version = 0;
}

pi_status_t pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                             pi_assign_extra_t *extra) {
  if (dev_id >= num_devices) return PI_STATUS_DEV_OUT_OF_RANGE;

  pi_device_info_t *info = &device_mapping[dev_id];
  if (info->version) return PI_STATUS_DEV_ALREADY_ASSIGNED;

  pi_status_t status = _pi_assign_device(dev_id, p4info, extra);
  if (status == PI_STATUS_SUCCESS) pi_update_device_config(dev_id, p4info);

  return status;
}

pi_status_t pi_remove_device(pi_dev_id_t dev_id) {
  if (dev_id >= num_devices) return PI_STATUS_DEV_OUT_OF_RANGE;

  pi_device_info_t *info = &device_mapping[dev_id];
  if (!info->version) return PI_STATUS_DEV_NOT_ASSIGNED;

  pi_status_t status = _pi_remove_device(dev_id);
  if (status == PI_STATUS_SUCCESS) pi_reset_device_config(dev_id);

  return status;
}

pi_status_t pi_destroy() {
  free(device_mapping);
  return _pi_destroy();
}

bool pi_is_action_id(pi_p4_id_t id) {
  return (id >> 24) == PI_ACTION_ID;
}

bool pi_is_table_id(pi_p4_id_t id) {
  return (id >> 24) == PI_TABLE_ID;
}

bool pi_is_action_param_id(pi_p4_id_t id) {
  return (id >> 24) == PI_ACTION_PARAM_ID;
}

bool pi_is_field_id(pi_p4_id_t id) {
  return (id >> 24) == PI_FIELD_ID;
}

size_t get_match_key_size(const pi_p4info_t *p4info, pi_p4_id_t table_id) {
  size_t s = 0;
  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, table_id);
  for (size_t i = 0; i < num_match_fields; i++) {
    pi_p4info_match_field_info_t finfo;
    pi_p4info_table_match_field_info(p4info, table_id, i, &finfo);
    s += get_match_key_size_one_field(finfo.match_type, finfo.bitwidth);
  }
  return s;
}

size_t get_action_data_size(const pi_p4info_t *p4info, pi_p4_id_t action_id) {
  size_t num_params;
  const pi_p4_id_t *params = pi_p4info_action_get_params(p4info, action_id,
                                                         &num_params);
  size_t s = 0;
  for (size_t i = 0; i < num_params; i++) {
    size_t bitwidth = pi_p4info_action_param_bitwidth(p4info, params[i]);
    s += (bitwidth + 7) / 8;
  }
  return s;
}
