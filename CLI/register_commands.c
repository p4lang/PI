/* Copyright 2026 Lorenzo Rinieri
 * SPDX-License-Identifier: Apache-2.0
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
#include "utils.h"

#include <PI/pi.h>
#include <PI/pi_register.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const pi_p4info_t *p4info_curr;
extern pi_dev_tgt_t dev_tgt;
extern pi_session_handle_t sess;

static char *complete_register(const char *text, int state) {
  static pi_res_type_id_t register_types[] = {PI_REGISTER_ID};
  return complete_one_name(text, state,
                           sizeof(register_types) / sizeof(pi_res_type_id_t),
                           register_types);
}

// args[0] is the register name, and args[1] the index if index is not NULL
static pi_cli_status_t parse_register(char *subcmd, const char **args,
                                      size_t num_args, pi_p4_id_t *r_id,
                                      size_t *index) {
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  *r_id = pi_p4info_register_id_from_name(p4info_curr, args[0]);
  if (*r_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_REGISTER_NAME;
  if (pi_p4info_register_get_bitwidth(p4info_curr, *r_id) == 0) {
    printf("The type of this register is not supported\n");
    return PI_CLI_STATUS_ERROR;
  }
  if (!index) return PI_CLI_STATUS_SUCCESS;
  char *endptr;
  *index = strtoull(args[1], &endptr, 0);
  if (*endptr != '\0' ||
      *index >= pi_p4info_register_get_size(p4info_curr, *r_id)) {
    printf("Invalid register index\n");
    return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  }
  return PI_CLI_STATUS_SUCCESS;
}

// value is a hexadecimal string, as for action parameters; returns NULL if it
// does not fit in a cell
static char *parse_register_value(pi_p4_id_t r_id, const char *value_str) {
  size_t bitwidth = pi_p4info_register_get_bitwidth(p4info_curr, r_id);
  size_t nbytes = (bitwidth + 7) / 8;
  char *value = malloc(nbytes);
  char mask = (bitwidth % 8 == 0) ? 0 : (char)(0xff << (bitwidth % 8));
  if (param_to_bytes(value_str, value, bitwidth) || (value[0] & mask)) {
    printf("Invalid register value\n");
    free(value);
    return NULL;
  }
  return value;
}

char register_read_hs[] =
    "Read the value of a register cell: "
    "register_read <register name> <index>";

pi_cli_status_t do_register_read(char *subcmd) {
  const char *args[2];
  pi_p4_id_t r_id;
  size_t index;
  pi_cli_status_t status = parse_register(subcmd, args, 2, &r_id, &index);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  size_t bitwidth = pi_p4info_register_get_bitwidth(p4info_curr, r_id);
  size_t nbytes = (bitwidth + 7) / 8;
  char *value = malloc(nbytes);
  pi_status_t rc = pi_register_read(sess, dev_tgt, r_id, index, value);
  if (rc != PI_STATUS_SUCCESS) {
    printf("Error when trying to read register\n");
    free(value);
    return PI_CLI_STATUS_TARGET_ERROR;
  }
  printf("%s[%zu] = 0x", args[0], index);
  print_hexstr(value, nbytes);
  printf("\n");
  free(value);
  return PI_CLI_STATUS_SUCCESS;
}

char *complete_register_read(const char *text, int state) {
  return complete_register(text, state);
}

char register_write_hs[] =
    "Write a value to a register cell: "
    "register_write <register name> <index> <value>";

pi_cli_status_t do_register_write(char *subcmd) {
  const char *args[3];
  pi_p4_id_t r_id;
  size_t index;
  pi_cli_status_t status = parse_register(subcmd, args, 3, &r_id, &index);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  char *value = parse_register_value(r_id, args[2]);
  if (!value) return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  pi_status_t rc = pi_register_write(sess, dev_tgt, r_id, index, value);
  free(value);
  if (rc != PI_STATUS_SUCCESS) {
    printf("Error when trying to write register\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }
  return PI_CLI_STATUS_SUCCESS;
}

char *complete_register_write(const char *text, int state) {
  return complete_register(text, state);
}

char register_write_all_hs[] =
    "Write the same value to all the cells of a register: "
    "register_write_all <register name> <value>";

pi_cli_status_t do_register_write_all(char *subcmd) {
  const char *args[2];
  pi_p4_id_t r_id;
  pi_cli_status_t status = parse_register(subcmd, args, 2, &r_id, NULL);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  char *value = parse_register_value(r_id, args[1]);
  if (!value) return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  pi_status_t rc = pi_register_write_all(sess, dev_tgt, r_id, value);
  free(value);
  if (rc != PI_STATUS_SUCCESS) {
    printf("Error when trying to write register\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }
  return PI_CLI_STATUS_SUCCESS;
}

char *complete_register_write_all(const char *text, int state) {
  return complete_register(text, state);
}

char register_reset_hs[] =
    "Reset all the cells of a register to 0: "
    "register_reset <register name>";

pi_cli_status_t do_register_reset(char *subcmd) {
  const char *args[1];
  pi_p4_id_t r_id;
  pi_cli_status_t status = parse_register(subcmd, args, 1, &r_id, NULL);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  size_t bitwidth = pi_p4info_register_get_bitwidth(p4info_curr, r_id);
  char *value = calloc((bitwidth + 7) / 8, 1);
  pi_status_t rc = pi_register_write_all(sess, dev_tgt, r_id, value);
  free(value);
  if (rc != PI_STATUS_SUCCESS) {
    printf("Error when trying to reset register\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }
  return PI_CLI_STATUS_SUCCESS;
}

char *complete_register_reset(const char *text, int state) {
  return complete_register(text, state);
}
