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

#include "error_codes.h"
#include "table_common.h"

char direct_res_reset_hs[] =
    "Remove direct resource configs which are kept ready for next table_add: "
    "direct_res_reset";

pi_cli_status_t do_direct_res_reset(char *subcmd) {
  // better way of doing this?
  if (subcmd && *subcmd != '\0') return PI_CLI_STATUS_TOO_MANY_ARGS;

  reset_direct_resource_configs();

  return PI_CLI_STATUS_SUCCESS;
}
