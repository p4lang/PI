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
