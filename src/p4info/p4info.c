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

#include "PI/pi_base.h"
#include "p4info_struct.h"
#include "config_readers/readers.h"
#include "actions_int.h"
#include "tables_int.h"
#include "fields_int.h"
#include "act_profs_int.h"
#include "utils/utils.h"

#include <cJSON/cJSON.h>

#include <stdlib.h>

pi_status_t pi_add_config(const char *config, pi_config_type_t config_type,
                          pi_p4info_t **p4info) {
  pi_status_t status;
  pi_p4info_t *p4info_ = malloc(sizeof(pi_p4info_t));
  switch (config_type) {
    case PI_CONFIG_TYPE_BMV2_JSON:
      status = pi_bmv2_json_reader(config, p4info_);
      break;
    case PI_CONFIG_TYPE_NATIVE_JSON:
      status = pi_native_json_reader(config, p4info_);
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
  pi_p4info_act_prof_free(p4info);
  free(p4info);
  return PI_STATUS_SUCCESS;
}

char *pi_serialize_config(const pi_p4info_t *p4info, int fmt) {
  cJSON *root = cJSON_CreateObject();
  pi_p4info_field_serialize(root, p4info);
  pi_p4info_action_serialize(root, p4info);
  pi_p4info_table_serialize(root, p4info);
  pi_p4info_act_prof_serialize(root, p4info);
  // TODO(antonin): use cJSON_PrintBuffered for better performance if needed
  char *str = (fmt) ? cJSON_Print(root) : cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  return str;
}
