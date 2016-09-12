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

// Generates the PI JSON from the Bmv2 JSON

#include <PI/pi.h>
#include <PI/p4info.h>

#include <stdio.h>

// TODO(antonin): this is just temporary, to ensure no logs go to stdout
extern void pi_logs_off();

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "P4 configuration needed.\n");
    fprintf(stderr, "Usage: %s <path to config>\n", argv[0]);
    return 1;
  }

  pi_logs_off();

  pi_status_t status;
  pi_p4info_t *p4info;
  status = pi_add_config_from_file(argv[1], PI_CONFIG_TYPE_BMV2_JSON, &p4info);
  if (status != PI_STATUS_SUCCESS) {
    fprintf(stderr, "Error while loading config.\n");
    return 1;
  }

  const char *native_json = pi_serialize_config(p4info, 1);

  printf("%s\n", native_json);

  return 0;
}
