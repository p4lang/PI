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
#include "table_indirect_common.h"

#include "PI/pi.h"
#include "PI/frontends/generic/pi.h"

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>

char table_indirect_create_member_hs[] =
    "Add a member to an indirect match table: "
    "table_indirect_create_member <table name> <action_name> "
    "[action parameters]";

pi_cli_status_t do_table_indirect_create_member(char *subcmd) {
  const char *args[2];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *act_prof_name = args[0];
  const char *action_name = args[1];
  pi_p4_id_t act_prof_id =
      pi_p4info_act_prof_id_from_name(p4info_curr, act_prof_name);
  if (act_prof_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;
  pi_p4_id_t action_id =
      pi_p4info_action_id_from_name(p4info_curr, action_name);
  if (action_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_ACTION_NAME;

  pi_cli_status_t status;

  pi_action_data_t *adata;
  pi_action_data_allocate(p4info_curr, action_id, &adata);
  pi_action_data_init(adata);
  status = read_action_data(NULL, action_id, adata);
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_action_data_destroy(adata);
    return status;
  }

  pi_indirect_handle_t mbr_handle = 0;
  pi_status_t rc;
  rc = pi_act_prof_mbr_create(sess, dev_tgt, act_prof_id, adata, &mbr_handle);
  if (rc == PI_STATUS_SUCCESS) {
    printf("Member was successfully created with handle %" PRIu64 ".\n",
           mbr_handle);
  } else {
    printf("Error when trying to create member.\n");
  }

  pi_action_data_destroy(adata);
  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
                                   : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_indirect_create_member(const char *text, int state) {
  return complete_act_prof_and_action(text, state);
}
