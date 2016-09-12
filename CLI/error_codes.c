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

const char *error_code_to_string(pi_cli_status_t error) {
  switch (error) {
    case PI_CLI_STATUS_SUCCESS:
      return "Success";
    case PI_CLI_STATUS_TARGET_ERROR:
      return "Target returned error code";
    case PI_CLI_STATUS_TOO_FEW_ARGS:
      return "Too few arguments";
    case PI_CLI_STATUS_TOO_MANY_ARGS:
      return "Too many arguments";
    case PI_CLI_STATUS_INVALID_TABLE_NAME:
      return "Invalid table name";
    case PI_CLI_STATUS_INVALID_ACTION_NAME:
      return "Invalid action name";
    case PI_CLI_STATUS_TOO_FEW_MATCH_FIELDS:
      return "Too few match fields";
    case PI_CLI_STATUS_INVALID_VALID_MATCH_FIELD:
      return "Invalid valid match field";
    case PI_CLI_STATUS_INVALID_EXACT_MATCH_FIELD:
      return "Invalid exact match field";
    case PI_CLI_STATUS_INVALID_LPM_MATCH_FIELD:
      return "Invalid LPM match field";
    case PI_CLI_STATUS_INVALID_TERNARY_MATCH_FIELD:
      return "Invalid ternary match field";
    case PI_CLI_STATUS_INVALID_RANGE_MATCH_FIELD:
      return "Invalid range match field";
    case PI_CLI_STATUS_INVALID_COMMAND_FORMAT:
      return "Invalid command format";
    case PI_CLI_STATUS_TOO_FEW_ACTION_PARAMS:
      return "Too few action params";
    case PI_CLI_STATUS_INVALID_ENTRY_HANDLE:
      return "Invalid entry handle";
    case PI_CLI_STATUS_INVALID_DEVICE_ID:
      return "Invalid device id";
    case PI_CLI_STATUS_INVALID_INDIRECT_HANDLE:
      return "Invalid indirect handle";
    case PI_CLI_STATUS_INVALID_P4_CONFIG_TYPE:
      return "Invalid P4 config type";
    case PI_CLI_STATUS_INVALID_P4_CONFIG:
      return "Invalid P4 config";
    case PI_CLI_STATUS_INVALID_P4_CONFIG_ID:
      return "Invalid P4 config id";
    case PI_CLI_STATUS_ERROR:
      return "Other error";
    case PI_CLI_STATUS_INVALID_COUNTER_NAME:
      return "Invalid counter name";
    case PI_CLI_STATUS_INVALID_METER_NAME:
      return "Invalid meter name";
    case PI_CLI_STATUS_INVALID_FILE_NAME:
      return "Invalid file name";
  }
  return "Unknown error";
}
