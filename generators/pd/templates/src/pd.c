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
  // no call to pi_init: pi is not initialized on a per P4-program basis
  return 0;
}

p4_pd_status_t ${pd_prefix}assign_device(int dev_id,
                                         const char *config_path) {
                                         /* const pd_assign_extra_t *extra) { */
  pi_status_t pi_status;

  pi_p4info_t *p4info;
  pi_status = pi_add_config_from_file(config_path, PI_CONFIG_TYPE_NATIVE_JSON,
                                      &p4info);
  assert(pi_status == PI_STATUS_SUCCESS);

  pi_assign_extra_t pi_extra[16];
  memset(pi_extra, 0, sizeof(pi_extra));
  pi_assign_extra_t *curr = &pi_extra[0];
  /* for (; !extra->end_of_extras; extra++) { */
  /*   curr->key = extra->key; */
  /*   curr->v = extra->v; */
  /*   curr++; */
  /* } */
  curr->end_of_extras = 1;

  pi_status = pi_assign_device(dev_id, p4info, pi_extra);
  assert(pi_status == PI_STATUS_SUCCESS);

  return 0;
}

p4_pd_status_t ${pd_prefix}remove_device(int dev_id) {
  assert(pi_remove_device(dev_id) == PI_STATUS_SUCCESS);
  return 0;
}
