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

#include "utils.h"
#include "error_codes.h"

#include "PI/pi.h"

#include <string.h>
#include <stdlib.h>

#include <readline/readline.h>

extern pi_p4info_t *p4info;
extern pi_dev_tgt_t dev_tgt;
extern int is_device_attached;

#define MAX_EXTRAS 16

char select_device_hs[] =
    "Connect to a specific device: "
    "select_device <device_id> [key=v;]*";

pi_cli_status_t do_select_device(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  char *endptr;
  uint16_t device_id = strtol(subcmd, &endptr, 0);
  if (*endptr != '\0') return PI_CLI_STATUS_INVALID_DEVICE_ID;

  pi_assign_extra_t extras[MAX_EXTRAS + 1];
  memset(extras, 0, sizeof(extras));
  size_t extra_idx = 0;

  char *token;
  const char *v;
  while (1) {
    v = NULL;
    token = strtok(NULL, ";");
    if (!token) break;
    for (; *token == ' '; token++);
    if (extra_idx >= MAX_EXTRAS) return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
    char *eq = strchr(token, '=');
    if (eq) {
      *eq = '\0';
      v = eq + 1;
      for (v = eq + 1; *v == ' '; v++);
      for (eq = eq - 1; *eq == ' ' && *eq != '\0'; eq--) *eq = '\0';
      for (char *endv = strchr(v, '\0') - 1; *endv == ' ' && endv >= v; endv--)
        *endv = '\0';
    }
    extras[extra_idx].key = token;
    extras[extra_idx].v = v;
    extra_idx++;
  }

  extras[extra_idx].end_of_extras = 1;

  pi_status_t rc = pi_assign_device(device_id, p4info, extras);
  if (rc == PI_STATUS_SUCCESS) {
    printf("Device selected successfully.\n");
    dev_tgt.dev_id = device_id;
    is_device_attached = 1;
    return PI_CLI_STATUS_SUCCESS;
  } else {
    printf("Failed to select device\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }
}
