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

#include "pd/pd.h"
#include <PI/pi.h>
#include <PI/p4info.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

p4_pd_status_t ${pd_prefix}init(void) {
  assert(pi_init(256, NULL) == PI_STATUS_SUCCESS);
  return 0;
}

p4_pd_status_t ${pd_prefix}assign_device(int dev_id,
                                         const char *notifications_addr,
                                         const char *config_path,
                                         int rpc_port_num) {
  (void) notifications_addr;
  pi_status_t pi_status;

  pi_p4info_t *p4info;
  pi_status = pi_add_config_from_file(config_path, PI_CONFIG_TYPE_NATIVE_JSON,
                                      &p4info);
  assert(pi_status == PI_STATUS_SUCCESS);

  pi_assign_extra_t extras[2];
  memset(extras, 0, sizeof(extras));

  char port_str[16];
  sprintf(port_str, "%d", rpc_port_num);
  extras[0].key = "port";
  extras[0].v = port_str;
  extras[1].end_of_extras = 1;

  pi_status = pi_assign_device(dev_id, p4info, extras);
  assert(pi_status == PI_STATUS_SUCCESS);

  return 0;
}

p4_pd_status_t ${pd_prefix}remove_device(int dev_id) {
  assert(pi_remove_device(dev_id) == PI_STATUS_SUCCESS);
  return 0;
}
