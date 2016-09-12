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

#ifndef PI_CLI_ERROR_CODES_H_
#define PI_CLI_ERROR_CODES_H_

typedef enum {
  PI_CLI_STATUS_SUCCESS = 0,
  PI_CLI_STATUS_TARGET_ERROR,
  PI_CLI_STATUS_TOO_FEW_ARGS,
  PI_CLI_STATUS_TOO_MANY_ARGS,
  PI_CLI_STATUS_INVALID_TABLE_NAME,
  PI_CLI_STATUS_INVALID_ACTION_NAME,
  PI_CLI_STATUS_TOO_FEW_MATCH_FIELDS,
  PI_CLI_STATUS_INVALID_VALID_MATCH_FIELD,
  PI_CLI_STATUS_INVALID_EXACT_MATCH_FIELD,
  PI_CLI_STATUS_INVALID_LPM_MATCH_FIELD,
  PI_CLI_STATUS_INVALID_TERNARY_MATCH_FIELD,
  PI_CLI_STATUS_INVALID_RANGE_MATCH_FIELD,
  PI_CLI_STATUS_INVALID_COMMAND_FORMAT,
  PI_CLI_STATUS_TOO_FEW_ACTION_PARAMS,
  PI_CLI_STATUS_INVALID_ENTRY_HANDLE,
  PI_CLI_STATUS_INVALID_DEVICE_ID,
  PI_CLI_STATUS_INVALID_INDIRECT_HANDLE,
  PI_CLI_STATUS_INVALID_P4_CONFIG_TYPE,
  PI_CLI_STATUS_INVALID_P4_CONFIG,
  PI_CLI_STATUS_INVALID_P4_CONFIG_ID,
  PI_CLI_STATUS_INVALID_COUNTER_NAME,
  PI_CLI_STATUS_INVALID_METER_NAME,
  PI_CLI_STATUS_INVALID_FILE_NAME,

  PI_CLI_STATUS_ERROR,
} pi_cli_status_t;

const char *error_code_to_string(pi_cli_status_t error);

#endif  // PI_CLI_ERROR_CODES_H_
