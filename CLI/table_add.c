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
#include "table_common.h"

#include "PI/pi.h"
#include "PI/frontends/generic/pi.h"

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>

char table_add_hs[] =
    "Add entry to a match table: "
    "table_add <table name> <action name> <match fields> => "
    "<action parameters> [priority]";

static int read_LPM_field(char *mf, int *pLen) {
  char *delim = strchr(mf, '/');
  if (!delim) return 1;
  *delim = '\0';
  delim++;
  if (*delim == '\0') return 1;
  char *endptr;
  *pLen = strtol(delim, &endptr, 10);
  if (*endptr != '\0') return 1;
  return 0;
}

static int read_ternary_field(char *mf, char **mask) {
  char *delim = strstr(mf, "&&&");
  if (!delim) return 1;
  *delim = '\0';
  delim += 3;
  if (*delim == '\0') return 1;
  *mask = delim;
  return 0;
}

#define BYTES_TEMP_SIZE 64

static int match_key_add_valid_field(pi_p4_id_t f_id, size_t f_bitwidth,
                                     char *mf, pi_match_key_t *mk) {
  (void) f_bitwidth;
  int v;
  if (!strncasecmp("true", mf, sizeof("true"))) {
    v = 1;
  } else if (!strncasecmp("false", mf, sizeof("false"))) {
    v = 0;
  } else {
    char *endptr;
    long int res = strtol(mf, &endptr, 0);
    if (*endptr != '\0') return 1;
    v = (res != 0);
  }
  // TODO(antonin)
  (void) v; (void) f_id; (void) mk;
  return 0;
}

static int match_key_add_exact_field(pi_p4_id_t f_id, size_t f_bitwidth,
                                     char *mf, pi_match_key_t *mk) {
  char bytes[BYTES_TEMP_SIZE];
  if (param_to_bytes(mf, bytes, f_bitwidth)) return 1;
  pi_netv_t f_netv;
  pi_status_t rc;
  rc = pi_getnetv_ptr(p4info, f_id, bytes, (f_bitwidth + 7) / 8, &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_match_key_exact_set(p4info, mk, &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  return 0;
}

static int match_key_add_LPM_field(pi_p4_id_t f_id, size_t f_bitwidth,
                                   char *mf, int pLen, pi_match_key_t *mk) {
  char bytes[BYTES_TEMP_SIZE];
  if (param_to_bytes(mf, bytes, f_bitwidth)) return 1;
  pi_netv_t f_netv;
  pi_status_t rc;
  rc = pi_getnetv_ptr(p4info, f_id, bytes, (f_bitwidth + 7) / 8, &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_match_key_lpm_set(p4info, mk, &f_netv, pLen);
  assert(rc == PI_STATUS_SUCCESS);
  return 0;
}

static int match_key_add_ternary_field(pi_p4_id_t f_id, size_t f_bitwidth,
                                       char *mf, char *mask,
                                       pi_match_key_t *mk) {
  char bytes[BYTES_TEMP_SIZE];
  char mask_bytes[BYTES_TEMP_SIZE];
  pi_status_t rc;
  if (param_to_bytes(mf, bytes, f_bitwidth)) return 1;
  if (param_to_bytes(mask, mask_bytes, f_bitwidth)) return 1;
  pi_netv_t f_netv, m_netv;
  size_t nbytes = (f_bitwidth + 7) / 8;
  rc = pi_getnetv_ptr(p4info, f_id, bytes, nbytes, &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_getnetv_ptr(p4info, f_id, mask_bytes, nbytes, &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_match_key_ternary_set(p4info, mk, &f_netv, &m_netv);
  assert(rc == PI_STATUS_SUCCESS);
  return 0;
}

static pi_cli_status_t read_match_fields(char *in, pi_p4_id_t t_id,
                                         pi_match_key_t *mk) {
  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, t_id);
  for (size_t i = 0; i < num_match_fields; i++) {
    pi_p4info_match_field_info_t finfo;
    pi_p4info_table_match_field_info(p4info, t_id, i, &finfo);
    pi_p4_id_t f_id = finfo.field_id;
    char *mf = strtok(in, " ");
    in = NULL;
    if (!mf || mf[0] == '=') return PI_CLI_STATUS_TOO_FEW_MATCH_FIELDS;
    int pLen;  // for LPM
    char *mask;  // for ternary
    switch (finfo.match_type) {
      case PI_P4INFO_MATCH_TYPE_VALID:
        if (match_key_add_valid_field(f_id, finfo.bitwidth, mf, mk))
          return PI_CLI_STATUS_INVALID_VALID_MATCH_FIELD;
        break;
      case PI_P4INFO_MATCH_TYPE_EXACT:
        if (match_key_add_exact_field(f_id, finfo.bitwidth, mf, mk))
          return PI_CLI_STATUS_INVALID_EXACT_MATCH_FIELD;
        break;
      case PI_P4INFO_MATCH_TYPE_LPM:
        if (read_LPM_field(mf, &pLen))
          return PI_CLI_STATUS_INVALID_LPM_MATCH_FIELD;
        if (match_key_add_LPM_field(f_id, finfo.bitwidth, mf, pLen, mk))
          return PI_CLI_STATUS_INVALID_LPM_MATCH_FIELD;
        break;
      case PI_P4INFO_MATCH_TYPE_TERNARY:
        if (read_ternary_field(mf, &mask))
          return PI_CLI_STATUS_INVALID_TERNARY_MATCH_FIELD;
        if (match_key_add_ternary_field(f_id, finfo.bitwidth, mf, mask, mk))
          return PI_CLI_STATUS_INVALID_TERNARY_MATCH_FIELD;
        break;
      default:
        // TODO: range
        assert(0);
    }
  }

  return PI_CLI_STATUS_SUCCESS;
}

pi_cli_status_t do_table_add(char *subcmd) {
  const char *args[2];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  const char *a_name = args[1];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, a_name);
  if (a_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_ACTION_NAME;

  pi_cli_status_t status;

  pi_match_key_t *mk;
  pi_match_key_allocate(p4info, t_id, &mk);
  pi_match_key_init(p4info, mk);
  status = read_match_fields(NULL, t_id, mk);
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_match_key_destroy(mk);
    return status;
  }

  char *separator = strtok(NULL, " ");
  if (!separator || strncmp("=>", separator, sizeof("=>"))) {
    pi_match_key_destroy(mk);
    fprintf(stderr, "Use '=>' to separate action data from match fields.\n");
    return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  }

  pi_action_data_t *adata;
  pi_action_data_allocate(p4info, a_id, &adata);
  pi_action_data_init(p4info, adata);
  status = read_action_data(NULL, a_id, adata);
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_match_key_destroy(mk);
    pi_action_data_destroy(adata);
    return status;
  }

  pi_entry_handle_t handle = 0;
  pi_table_entry_t t_entry = {a_id, adata, NULL, NULL};
  pi_status_t rc;
  rc = pi_table_entry_add(dev_tgt, t_id, mk, &t_entry, 0, &handle);
  if (rc == PI_STATUS_SUCCESS)
    printf("Entry was successfully added with handle %" PRIu64 ".\n", handle);
  else
    printf("Error when trying to add entry.\n");

  pi_match_key_destroy(mk);
  pi_action_data_destroy(adata);
  return (rc == PI_STATUS_SUCCESS) ? PI_CLI_STATUS_SUCCESS
      : PI_CLI_STATUS_TARGET_ERROR;
};

char *complete_table_add(const char *text, int state) {
  return complete_table_and_action(text, state);
}
