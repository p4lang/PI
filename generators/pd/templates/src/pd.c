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
