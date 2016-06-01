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
#include "target/pi_imp.h"
#include "p4info/p4info_struct.h"
#include "p4info/actions_int.h"
#include "p4info/tables_int.h"
#include "p4info/fields_int.h"
#include "config_readers/readers.h"
#include "pi_int.h"
#include "utils/utils.h"

#include <stdlib.h>

#define MAX_DEVICES 256

typedef struct {
  int assigned;
  int backend_id;
  const pi_p4info_t *p4info;
} device_info_t;

static size_t num_devices;
static device_info_t *device_mapping;

const pi_p4info_t *pi_get_device_p4info(uint16_t dev_id) {
  return device_mapping[dev_id].p4info;
}

pi_status_t pi_init(size_t max_devices) {
  num_devices = max_devices;
  device_mapping = calloc(max_devices, sizeof(device_info_t));
  return _pi_init();
}

pi_status_t pi_add_config(const char *config, pi_config_type_t config_type,
                          pi_p4info_t **p4info) {
  pi_status_t status;
  pi_p4info_t *p4info_ = malloc(sizeof(pi_p4info_t));
  switch (config_type) {
    case PI_CONFIG_TYPE_BMV2_JSON:
      status = pi_bmv2_json_reader(config, p4info_);
      break;
    default:
      status = PI_STATUS_INVALID_CONFIG_TYPE;
      break;
  }
  if (status != PI_STATUS_SUCCESS) {
    free(p4info_);
    return status;
  }
  *p4info = p4info_;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_add_config_from_file(const char *config_path,
                                    pi_config_type_t config_type,
                                    pi_p4info_t **p4info) {
  char *config_tmp = read_file(config_path);
  pi_status_t rc = pi_add_config(config_tmp, config_type, p4info);
  free(config_tmp);
  return rc;
}

pi_status_t pi_destroy_config(pi_p4info_t *p4info) {
  pi_p4info_action_free(p4info);
  pi_p4info_table_free(p4info);
  pi_p4info_field_free(p4info);
  free(p4info);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_assign_device(uint16_t dev_id, const pi_p4info_t *p4info,
                             pi_assign_extra_t *extra) {
  if (dev_id >= num_devices) return PI_STATUS_DEV_OUT_OF_RANGE;
  device_info_t *info = &device_mapping[dev_id];
  if (info->assigned) return PI_STATUS_DEV_ALREADY_ASSIGNED;
  pi_status_t status = _pi_assign_device(dev_id, p4info, extra);
  if (status == PI_STATUS_SUCCESS) {
    info->assigned = 1;
  }
  return status;
}

pi_status_t pi_remove_device(uint16_t dev_id) {
  if (dev_id >= num_devices) return PI_STATUS_DEV_OUT_OF_RANGE;
  device_info_t *info = &device_mapping[dev_id];
  if (!info->assigned) return PI_STATUS_DEV_NOT_ASSIGNED;
  pi_status_t status = _pi_remove_device(dev_id);
  if (status == PI_STATUS_SUCCESS) {
    info->assigned = 0;
  }
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
    size_t nbytes = (finfo.bitwidth + 7) / 8;
    switch (finfo.match_type) {
      case PI_P4INFO_MATCH_TYPE_VALID:
        assert(nbytes == 1);
      case PI_P4INFO_MATCH_TYPE_EXACT:
        s += nbytes;
        break;
      case PI_P4INFO_MATCH_TYPE_LPM:
        s += nbytes + sizeof(uint32_t);
        break;
      case PI_P4INFO_MATCH_TYPE_TERNARY:
      case PI_P4INFO_MATCH_TYPE_RANGE:
        s += 2 * nbytes;
        break;
      default:
        assert(0);
    }
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
