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

#include "error_codes.h"

const char *error_code_to_string(pi_cli_status_t error) {
  switch (error) {
    case PI_CLI_STATUS_SUCCESS:
      return "Success";
    case PI_CLI_STATUS_TOO_FEW_ARGS:
      return "Too few arguments";
    case PI_CLI_STATUS_INVALID_TABLE_NAME:
      return "Invalid table name";
    case PI_CLI_STATUS_INVALID_ACTION_NAME:
      return "Invalid action name";
  }
  return "Unknown error";
}
