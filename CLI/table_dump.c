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

// temporary
struct pi_match_key_s {
  const pi_p4info_t *p4info;
  char *data;
};

// temporary
struct pi_action_data_s {
  const pi_p4info_t *p4info;
  char *data;
};

char table_dump_hs[] =
    "Dump all entries in a match table: table_dump <table name>";

static int get_name_out_width(int min, pi_p4_id_t t_id) {
  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, t_id);
  size_t max = min;
  for (size_t j = 0; j < num_match_fields; j++) {
    pi_p4info_match_field_info_t finfo;
    pi_p4info_table_match_field_info(p4info, t_id, j, &finfo);
    size_t L = strlen(finfo.name);
    max = (L > max) ? L : max;
  }
  return (int) max;
}

static const char *match_type_to_str(pi_p4info_match_type_t mt) {
  switch(mt) {
    case PI_P4INFO_MATCH_TYPE_VALID:
      return "VALID";
    case PI_P4INFO_MATCH_TYPE_EXACT:
      return "EXACT";
    case PI_P4INFO_MATCH_TYPE_LPM:
      return "LPM";
    case PI_P4INFO_MATCH_TYPE_TERNARY:
      return "TERNARY";
    case PI_P4INFO_MATCH_TYPE_RANGE:
      return "RANGE";
    default:
      assert(0);
  }
}

static void print_hexstr(const char *bytes, size_t nbytes) {
  for (size_t i = 0; i < nbytes; i++) {
    printf("%02x", bytes[i]);
  }
}

static void print_match_param_v(pi_p4info_match_type_t mt, const char *d,
                                size_t bitwidth) {
  size_t nbytes = (bitwidth + 7) / 8;
  switch(mt) {
    case PI_P4INFO_MATCH_TYPE_VALID:
      // TODO(antonin)
      break;
    case PI_P4INFO_MATCH_TYPE_EXACT:
      print_hexstr(d, nbytes);
      d += nbytes;
      break;
    case PI_P4INFO_MATCH_TYPE_LPM:
      print_hexstr(d, nbytes);
      d += nbytes;
      uint32_t pLen;
      memcpy(&pLen, d, sizeof(pLen));
      d += sizeof(pLen);
      printf("/%u", pLen);
      break;
    case PI_P4INFO_MATCH_TYPE_TERNARY:
      print_hexstr(d, nbytes);
      d += nbytes;
      printf(" &&& ");
      print_hexstr(d, nbytes);
      d += nbytes;
    case PI_P4INFO_MATCH_TYPE_RANGE:
      break;
    default:
      assert(0);
  }
}

static void print_action_entry(pi_table_entry_t *entry) {
  // TODO(antonin): all types of action entries (indirect)
  pi_p4_id_t action_id = entry->action_id;
  const char *action_name = pi_p4info_action_name_from_id(p4info, action_id);
  printf("Action entry: %s - ", action_name);
  size_t num_params;
  const pi_p4_id_t *param_ids = pi_p4info_action_get_params(p4info, action_id,
                                                            &num_params);
  const char *action_data = entry->action_data->data;
  for (size_t j = 0; j < num_params; j++) {
    size_t bitwidth = pi_p4info_action_param_bitwidth(p4info, param_ids[j]);
    size_t nbytes = (bitwidth + 7) / 8;
    print_hexstr(action_data, nbytes);
    action_data += nbytes;

    if (j != num_params - 1) printf(", ");
  }
  printf("\n");
}

static pi_cli_status_t dump_entries(pi_p4_id_t t_id,
                                    pi_table_fetch_res_t *res) {
  printf("==========\n");
  printf("TABLE ENTRIES\n");

  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, t_id);

  const int name_out_width = get_name_out_width(20, t_id);

  pi_table_ma_entry_t entry;
  pi_entry_handle_t entry_handle;
  size_t num_entries = pi_table_entries_num(res);
  for (size_t i = 0; i < num_entries; i++) {
    printf("**********\n");
    pi_table_entries_next(res, &entry, &entry_handle);
    printf("Dumping entry %" PRIu64 "\n", entry_handle);

    printf("Match key:\n");
    for (size_t j = 0; j < num_match_fields; j++) {
      pi_p4info_match_field_info_t finfo;
      pi_p4info_table_match_field_info(p4info, t_id, j, &finfo);
      printf("* %-*s: %-10s", name_out_width, finfo.name,
             match_type_to_str(finfo.match_type));
      print_match_param_v(finfo.match_type, entry.match_key->data,
                          finfo.bitwidth);
      printf("\n");
    }
    // TODO(antonin): print priority

    print_action_entry(&entry.entry);
  }

  // TODO(antonin): default entry
  printf("==========\n");
  printf("Dumping default entry\n");
  printf("TODO\n");

  printf("==========\n");

  return PI_CLI_STATUS_SUCCESS;
}

pi_cli_status_t do_table_dump(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;

  pi_cli_status_t status = PI_CLI_STATUS_SUCCESS;

  pi_table_fetch_res_t *res;
  pi_status_t rc;
  rc = pi_table_entries_fetch(dev_tgt.dev_id, t_id, &res);
  if (rc == PI_STATUS_SUCCESS) {
    printf("Successfully retrieved %zu entrie(s).\n",
           pi_table_entries_num(res));
    status = dump_entries(t_id, res);
  } else {
    printf("Error when trying to retrieve entries.\n");
    status = PI_CLI_STATUS_TARGET_ERROR;
  }

  pi_table_entries_fetch_done(res);
  return status;
};

char *complete_table_dump(const char *text, int state) {
  return complete_table(text, state);
}
