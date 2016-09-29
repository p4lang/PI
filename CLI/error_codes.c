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
