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

#include "utils.h"
#include "error_codes.h"
#include "table_common.h"

#include "PI/pi.h"
#include "PI/frontends/generic/pi.h"

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>

char table_set_default_hs[] =
    "Set default entry in a match table: "
    "table_set_default <table name> "
    "[<action name> <action parameters> | <indirect handle>]";

pi_cli_status_t do_table_set_default(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info_curr, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;

  pi_cli_status_t status;

  pi_p4_id_t t_imp = pi_p4info_table_get_implementation(p4info_curr, t_id);

  pi_table_entry_t t_entry;
  if (t_imp == PI_INVALID_ID) {
    status = get_entry_direct(&t_entry);
  } else {
    status = get_entry_indirect(&t_entry);
  }
  if (status != PI_CLI_STATUS_SUCCESS) {
    return status;
  }

  t_entry.entry_properties = NULL;
  t_entry.direct_res_config = NULL;

  pi_status_t rc;
  rc = pi_table_default_action_set(sess, dev_tgt, t_id, &t_entry);
  if (rc == PI_STATUS_SUCCESS)
    printf("Default entry was successfully set.\n");
  else
    printf("Error when trying to set default entry.\n");

  if (t_imp == PI_INVALID_ID)
    cleanup_entry_direct(&t_entry);
  else
    cleanup_entry_indirect(&t_entry);

  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_set_default(const char *text, int state) {
  return complete_table(text, state);
}
