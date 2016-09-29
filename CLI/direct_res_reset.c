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
