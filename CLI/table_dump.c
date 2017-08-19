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

#include "_assert.h"
#include "error_codes.h"
#include "table_common.h"
#include "utils.h"

#include "PI/frontends/generic/pi.h"
#include "PI/pi.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char table_dump_hs[] =
    "Dump all entries in a match table: table_dump <table name>";

static int get_name_out_width(int min, pi_p4_id_t t_id) {
  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info_curr, t_id);
  size_t max = min;
  for (size_t j = 0; j < num_match_fields; j++) {
    const pi_p4info_match_field_info_t *finfo =
        pi_p4info_table_match_field_info(p4info_curr, t_id, j);
    size_t L = strlen(finfo->name);
    max = (L > max) ? L : max;
  }
  return (int)max;
}

static const char *match_type_to_str(pi_p4info_match_type_t mt) {
  switch (mt) {
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
      _PI_UNREACHABLE("Invalid switch statement");
  }
}

// clang-format off
static void print_match_param_v(pi_p4_id_t f_id, pi_p4info_match_type_t mt,
                                const pi_match_key_t *match_key) {
  pi_netv_t fv;
  switch (mt) {
    case PI_P4INFO_MATCH_TYPE_VALID:
    case PI_P4INFO_MATCH_TYPE_EXACT:
      pi_match_key_exact_get(match_key, f_id, &fv);
      print_hexstr(fv.v.ptr, fv.size);
      break;
    case PI_P4INFO_MATCH_TYPE_LPM:;
      pi_prefix_length_t pLen;
      pi_match_key_lpm_get(match_key, f_id, &fv, &pLen);
      print_hexstr(fv.v.ptr, fv.size);
      printf("/%u", pLen);
      break;
    case PI_P4INFO_MATCH_TYPE_TERNARY:;
      pi_netv_t fv_mask;
      pi_match_key_ternary_get(match_key, f_id, &fv, &fv_mask);
      print_hexstr(fv.v.ptr, fv.size);
      printf(" &&& ");
      print_hexstr(fv_mask.v.ptr, fv_mask.size);
      break;
    case PI_P4INFO_MATCH_TYPE_RANGE:
      break;
    default:
      assert(0);
  }
}
// clang-format on

static void print_action_entry(pi_table_entry_t *entry) {
  // TODO(antonin): all types of action entries (indirect)

  if (entry->entry_type == PI_ACTION_ENTRY_TYPE_NONE) {
    printf("EMPTY\n");
    return;
  }

  if (entry->entry_type == PI_ACTION_ENTRY_TYPE_INDIRECT) {
    printf("Indirect handle: %" PRIu64 "\n", entry->entry.indirect_handle);
    return;
  }

  print_action_data(entry->entry.action_data);
}

static pi_cli_status_t dump_entries(pi_p4_id_t t_id,
                                    pi_table_fetch_res_t *res) {
  printf("==========\n");
  printf("TABLE ENTRIES\n");

  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info_curr, t_id);

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
      const pi_p4info_match_field_info_t *finfo =
          pi_p4info_table_match_field_info(p4info_curr, t_id, j);
      printf("* %-*s: %-10s", name_out_width, finfo->name,
             match_type_to_str(finfo->match_type));
      print_match_param_v(finfo->mf_id, finfo->match_type, entry.match_key);
      printf("\n");
    }

    uint32_t priority = pi_match_key_get_priority(entry.match_key);
    // TODO(antonin): bmv2 quirk, for tables with no priority, -1 is returned
    if (priority != (uint32_t)-1) printf("Priority: %u\n", priority);

    print_action_entry(&entry.entry);
  }

  printf("==========\n");

  return PI_CLI_STATUS_SUCCESS;
}

static pi_cli_status_t dump_default_entry(pi_p4_id_t t_id) {
  pi_status_t rc;
  pi_table_entry_t entry;
  rc = pi_table_default_action_get(sess, dev_tgt.dev_id, t_id, &entry);
  if (rc == PI_STATUS_SUCCESS) {
    printf("Dumping default entry\n");
    print_action_entry(&entry);
    printf("==========\n");
    pi_table_default_action_done(sess, &entry);
    return PI_CLI_STATUS_SUCCESS;
  } else {
    return PI_CLI_STATUS_TARGET_ERROR;
  }
}

pi_cli_status_t do_table_dump(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *t_name = args[0];
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info_curr, t_name);
  if (t_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;

  pi_cli_status_t status = PI_CLI_STATUS_SUCCESS;

  pi_table_fetch_res_t *res;
  pi_status_t rc;
  rc = pi_table_entries_fetch(sess, dev_tgt.dev_id, t_id, &res);
  if (rc == PI_STATUS_SUCCESS) {
    printf("Successfully retrieved %zu entrie(s).\n",
           pi_table_entries_num(res));
    status = dump_entries(t_id, res);
    pi_table_entries_fetch_done(sess, res);

    if (status == PI_CLI_STATUS_SUCCESS) status = dump_default_entry(t_id);
  } else {
    printf("Error when trying to retrieve entries.\n");
    status = PI_CLI_STATUS_TARGET_ERROR;
  }

  return status;
};

char *complete_table_dump(const char *text, int state) {
  return complete_table(text, state);
}
