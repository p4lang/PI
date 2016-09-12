/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "utils.h"
#include "table_common.h"
#include "vector.h"

#include "PI/pi.h"
#include "PI/frontends/generic/pi.h"

#include <string.h>
#include <stdlib.h>

#include <readline/readline.h>

#define BYTES_TEMP_SIZE 64

static vector_t *direct_res_configs = NULL;

pi_cli_status_t read_action_data(char *in, pi_p4_id_t a_id,
                                 pi_action_data_t *adata) {
  size_t num_params;
  const pi_p4_id_t *param_ids =
      pi_p4info_action_get_params(p4info_curr, a_id, &num_params);
  for (size_t i = 0; i < num_params; i++) {
    pi_p4_id_t p_id = param_ids[i];
    size_t p_bitwidth = pi_p4info_action_param_bitwidth(p4info_curr, p_id);
    char *ap = strtok(in, " ");
    in = NULL;
    if (!ap || ap[0] == '=') return PI_CLI_STATUS_TOO_FEW_ACTION_PARAMS;

    char bytes[BYTES_TEMP_SIZE];
    if (param_to_bytes(ap, bytes, p_bitwidth)) return 1;
    pi_netv_t p_netv;
    pi_status_t rc;
    rc =
        pi_getnetv_ptr(p4info_curr, p_id, bytes, (p_bitwidth + 7) / 8, &p_netv);
    assert(rc == PI_STATUS_SUCCESS);
    rc = pi_action_data_arg_set(adata, &p_netv);
    assert(rc == PI_STATUS_SUCCESS);
  }

  return PI_CLI_STATUS_SUCCESS;
}

char *complete_table(const char *text, int state) {
  static int token_count;
  static int len;

  if (!state) {
    token_count = count_tokens(rl_line_buffer);
    len = strlen(text);
  }

  if (token_count == 0) {  // just the cmd
    return NULL;
  } else if (token_count == 1) {
    return complete_p4_table(text, len, state);
  }
  return NULL;
}

char *complete_table_and_action(const char *text, int state) {
  static int token_count;
  static int len;
  static char *t_name;

  if (!state) {
    token_count = count_tokens(rl_line_buffer);
    len = strlen(text);
    if (t_name) free(t_name);
    t_name = NULL;
  }

  if (token_count == 0) {  // just the cmd
    return NULL;
  } else if (token_count == 1) {
    return complete_p4_table(text, len, state);
  } else if (token_count == 2) {
    if (!t_name) t_name = get_token_from_buffer(rl_line_buffer, 1);
    assert(t_name);
    return complete_p4_action(text, len, state, t_name);
  }
  return NULL;
}

pi_cli_status_t get_entry_direct(pi_table_entry_t *t_entry) {
  pi_cli_status_t status = PI_CLI_STATUS_SUCCESS;
  const char *a_name = strtok(NULL, " ");

  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info_curr, a_name);
  if (a_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_ACTION_NAME;

  t_entry->entry_type = PI_ACTION_ENTRY_TYPE_DATA;

  pi_action_data_allocate(p4info_curr, a_id, &t_entry->entry.action_data);
  pi_action_data_t *adata = t_entry->entry.action_data;
  pi_action_data_init(adata);
  status = read_action_data(NULL, a_id, adata);
  if (status != PI_CLI_STATUS_SUCCESS) {
    pi_action_data_destroy(adata);
    return status;
  }

  return status;
}

pi_cli_status_t get_entry_indirect(pi_table_entry_t *t_entry) {
  const char *handle_str = strtok(NULL, " ");
  char *endptr;
  pi_indirect_handle_t handle = strtoll(handle_str, &endptr, 0);
  if (*endptr != '\0') return PI_CLI_STATUS_INVALID_INDIRECT_HANDLE;
  t_entry->entry_type = PI_ACTION_ENTRY_TYPE_INDIRECT;
  t_entry->entry.indirect_handle = handle;
  return PI_CLI_STATUS_SUCCESS;
}

void cleanup_entry_direct(pi_table_entry_t *t_entry) {
  pi_action_data_destroy(t_entry->entry.action_data);
}

void cleanup_entry_indirect(pi_table_entry_t *t_entry) { (void)t_entry; }

void store_direct_resource_config(pi_p4_id_t res_id, void *config) {
  if (!direct_res_configs) {
    direct_res_configs = vector_create(sizeof(pi_direct_res_config_one_t), 4);
    assert(direct_res_configs);
  }
  pi_direct_res_config_one_t stored_config = {res_id, config};
  vector_push_back(direct_res_configs, &stored_config);
}

pi_direct_res_config_one_t *retrieve_direct_resource_configs(
    size_t *num_configs) {
  if (!direct_res_configs) {
    *num_configs = 0;
    return NULL;
  }
  *num_configs = vector_size(direct_res_configs);
  return vector_data(direct_res_configs);
}

void reset_direct_resource_configs() {
  if (direct_res_configs) {
    size_t v_size = vector_size(direct_res_configs);
    for (size_t i = 0; i < v_size; i++) {
      pi_direct_res_config_one_t *stored_config =
          vector_at(direct_res_configs, i);
      free(stored_config->config);
    }
    vector_destroy(direct_res_configs);
    direct_res_configs = NULL;
  }
}
