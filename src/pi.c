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

#include <stdlib.h>

#define MAX_DEVICES 256

pi_p4info_t *_device_mapping[MAX_DEVICES];

const pi_p4info_t *pi_get_device_p4info(uint16_t dev_id) {
  return _device_mapping[dev_id];
}

pi_status_t pi_init() {
  return _pi_init();
}

pi_status_t pi_add_config(const char *config, pi_p4info_t **p4info) {
  pi_status_t status;
  pi_p4info_t *p4info_ = malloc(sizeof(pi_p4info_t));
  if ((status = pi_bmv2_json_reader(config, p4info_)) != PI_STATUS_SUCCESS) {
    return status;
  }
  *p4info = p4info_;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_add_config_from_file(const char *config_path,
                                      pi_p4info_t **p4info) {
  (void) config_path; (void) p4info;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_destroy_config(pi_p4info_t *p4info) {
  pi_p4info_action_free(p4info);
  pi_p4info_table_free(p4info);
  pi_p4info_field_free(p4info);
  free(p4info);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_assign_device(uint16_t dev_id, const pi_p4info_t *p4info) {
  (void) dev_id; (void) p4info;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_remove_device(uint16_t dev_id) {
  (void) dev_id;
  return PI_STATUS_SUCCESS;
}
