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

#include "act_prof_common.h"
#include "error_codes.h"
#include "table_common.h"
#include "utils.h"

#include "PI/frontends/generic/pi.h"
#include "PI/pi.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char act_prof_dump_hs[] =
    "Dump entries of action profile: act_prof_dump <act_prof_name>";

static pi_cli_status_t dump_entries(pi_p4_id_t act_prof_id,
                                    pi_act_prof_fetch_res_t *res) {
  printf("==========\n");
  printf("MEMBERS\n");

  size_t num_members = pi_act_prof_mbrs_num(res);
  pi_action_data_t *action_data;
  pi_indirect_handle_t mbr_handle;
  for (size_t i = 0; i < num_members; i++) {
    printf("**********\n");
    pi_act_prof_mbrs_next(res, &action_data, &mbr_handle);
    printf("Dumping member %" PRIu64 "\n", mbr_handle);
    print_action_data(action_data);
  }

  if (pi_p4info_act_prof_has_selector(p4info_curr, act_prof_id)) {
    printf("==========\n");
    printf("GROUPS\n");

    pi_indirect_handle_t *mbr_handles;
    size_t num_mbrs;
    pi_indirect_handle_t grp_handle;
    size_t num_grps = pi_act_prof_grps_num(res);
    for (size_t i = 0; i < num_grps; i++) {
      printf("**********\n");
      pi_act_prof_grps_next(res, &mbr_handles, &num_mbrs, &grp_handle);
      printf("Dumping group %" PRIu64 "\n", grp_handle);

      printf("Members: [");
      for (size_t j = 0; j < num_mbrs; j++) {
        if (j > 0) printf(", ");
        printf("%" PRIu64, mbr_handles[j]);
      }
      printf("]\n");
    }
  }

  return PI_CLI_STATUS_SUCCESS;
}

pi_cli_status_t do_act_prof_dump(char *subcmd) {
  const char *args[1];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *act_prof_name = args[0];
  pi_p4_id_t act_prof_id =
      pi_p4info_act_prof_id_from_name(p4info_curr, act_prof_name);
  if (act_prof_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_TABLE_NAME;

  pi_cli_status_t status;

  pi_act_prof_fetch_res_t *res;
  pi_status_t rc;
  rc = pi_act_prof_entries_fetch(sess, dev_tgt.dev_id, act_prof_id, &res);
  if (rc == PI_STATUS_SUCCESS) {
    printf("Successfully retrieved %zu member(s) and %zu group(s).\n",
           pi_act_prof_mbrs_num(res), pi_act_prof_grps_num(res));
    status = dump_entries(act_prof_id, res);
    pi_act_prof_entries_fetch_done(sess, res);
  } else {
    printf("Error when trying to retrieve entries.\n");
    status = PI_CLI_STATUS_TARGET_ERROR;
  }

  return status;
};

char *complete_act_prof_dump(const char *text, int state) {
  return complete_act_prof(text, state);
}
