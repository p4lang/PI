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

#include "table_common.h"
#include "utils.h"
#include "vector.h"

#include "PI/frontends/generic/pi.h"
#include "PI/pi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <readline/readline.h>

#define BYTES_TEMP_SIZE 64

static vector_t *direct_res_configs = NULL;

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

static int match_key_add_valid_field(pi_p4_id_t t_id, pi_p4_id_t f_id,
                                     size_t f_bitwidth, char *mf,
                                     pi_match_key_t *mk) {
  (void)f_bitwidth;
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
  pi_netv_t f_netv;
  pi_status_t rc;
  rc = pi_getnetv_u8(p4info_curr, t_id, f_id, (uint8_t)v, &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_match_key_exact_set(mk, &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  return 0;
}

static int match_key_add_exact_field(pi_p4_id_t t_id, pi_p4_id_t f_id,
                                     size_t f_bitwidth, char *mf,
                                     pi_match_key_t *mk) {
  char bytes[BYTES_TEMP_SIZE];
  if (param_to_bytes(mf, bytes, f_bitwidth)) return 1;
  pi_netv_t f_netv;
  pi_status_t rc;
  rc = pi_getnetv_ptr(p4info_curr, t_id, f_id, bytes, (f_bitwidth + 7) / 8,
                      &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_match_key_exact_set(mk, &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  return 0;
}

static int match_key_add_LPM_field(pi_p4_id_t t_id, pi_p4_id_t f_id,
                                   size_t f_bitwidth, char *mf, int pLen,
                                   pi_match_key_t *mk) {
  char bytes[BYTES_TEMP_SIZE];
  if (param_to_bytes(mf, bytes, f_bitwidth)) return 1;
  pi_netv_t f_netv;
  pi_status_t rc;
  rc = pi_getnetv_ptr(p4info_curr, t_id, f_id, bytes, (f_bitwidth + 7) / 8,
                      &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_match_key_lpm_set(mk, &f_netv, pLen);
  assert(rc == PI_STATUS_SUCCESS);
  return 0;
}

static int match_key_add_ternary_field(pi_p4_id_t t_id, pi_p4_id_t f_id,
                                       size_t f_bitwidth, char *mf, char *mask,
                                       pi_match_key_t *mk) {
  char bytes[BYTES_TEMP_SIZE];
  char mask_bytes[BYTES_TEMP_SIZE];
  pi_status_t rc;
  if (param_to_bytes(mf, bytes, f_bitwidth)) return 1;
  if (param_to_bytes(mask, mask_bytes, f_bitwidth)) return 1;
  pi_netv_t f_netv, m_netv;
  size_t nbytes = (f_bitwidth + 7) / 8;
  rc = pi_getnetv_ptr(p4info_curr, t_id, f_id, bytes, nbytes, &f_netv);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_getnetv_ptr(p4info_curr, t_id, f_id, mask_bytes, nbytes, &m_netv);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_match_key_ternary_set(mk, &f_netv, &m_netv);
  assert(rc == PI_STATUS_SUCCESS);
  return 0;
}

pi_cli_status_t read_match_fields(char *in, pi_p4_id_t t_id,
                                  pi_match_key_t *mk) {
  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info_curr, t_id);
  for (size_t i = 0; i < num_match_fields; i++) {
    const pi_p4info_match_field_info_t *finfo =
        pi_p4info_table_match_field_info(p4info_curr, t_id, i);
    pi_p4_id_t f_id = finfo->mf_id;
    char *mf = strtok(in, " ");
    in = NULL;
    if (!mf || mf[0] == '=') return PI_CLI_STATUS_TOO_FEW_MATCH_FIELDS;
    int pLen;    // for LPM
    char *mask;  // for ternary
    switch (finfo->match_type) {
      case PI_P4INFO_MATCH_TYPE_VALID:
        if (match_key_add_valid_field(t_id, f_id, finfo->bitwidth, mf, mk))
          return PI_CLI_STATUS_INVALID_VALID_MATCH_FIELD;
        break;
      case PI_P4INFO_MATCH_TYPE_EXACT:
        if (match_key_add_exact_field(t_id, f_id, finfo->bitwidth, mf, mk))
          return PI_CLI_STATUS_INVALID_EXACT_MATCH_FIELD;
        break;
      case PI_P4INFO_MATCH_TYPE_LPM:
        if (read_LPM_field(mf, &pLen))
          return PI_CLI_STATUS_INVALID_LPM_MATCH_FIELD;
        if (match_key_add_LPM_field(t_id, f_id, finfo->bitwidth, mf, pLen, mk))
          return PI_CLI_STATUS_INVALID_LPM_MATCH_FIELD;
        break;
      case PI_P4INFO_MATCH_TYPE_TERNARY:
        if (read_ternary_field(mf, &mask))
          return PI_CLI_STATUS_INVALID_TERNARY_MATCH_FIELD;
        if (match_key_add_ternary_field(t_id, f_id, finfo->bitwidth, mf, mask,
                                        mk))
          return PI_CLI_STATUS_INVALID_TERNARY_MATCH_FIELD;
        break;
      default:
        // TODO: range
        assert(0);
    }
  }

  return PI_CLI_STATUS_SUCCESS;
}

// priority either comes as last argument on the command line or before '=>'
int read_priority(char *in, int *priority, const char *end) {
  const char *delim = " \t\n\v\f\r";

  char *pri_str = strtok(in, delim);
  if (!pri_str && !end) return 1;
  if (!pri_str) return 2;
  if (!strcmp(end, pri_str)) return 1;
  char *endptr;
  *priority = strtol(pri_str, &endptr, 0);
  if (*endptr != '\0') return 3;
  return 0;
}

pi_cli_status_t read_match_key_with_priority(char *in, pi_p4_id_t t_id,
                                             pi_match_key_t *mk,
                                             const char *end) {
  int priority;
  pi_match_key_init(mk);
  pi_cli_status_t status = read_match_fields(in, t_id, mk);
  if (status != PI_CLI_STATUS_SUCCESS) {
    return status;
  }
  int pri_status = read_priority(NULL, &priority, end);
  if (pri_status == 1) {
    // no priority
  } else if (pri_status == 2) {
    fprintf(stderr, "Expected '%s' after match key.\n", end);
    return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  } else if (pri_status == 3 || priority < 0) {
    return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  } else {  // success
    pi_match_key_set_priority(mk, priority);
  }
  return PI_CLI_STATUS_SUCCESS;
}

pi_cli_status_t read_action_data(char *in, pi_p4_id_t a_id,
                                 pi_action_data_t *adata) {
  size_t num_params;
  const pi_p4_id_t *param_ids =
      pi_p4info_action_get_params(p4info_curr, a_id, &num_params);
  for (size_t i = 0; i < num_params; i++) {
    pi_p4_id_t p_id = param_ids[i];
    size_t p_bitwidth =
        pi_p4info_action_param_bitwidth(p4info_curr, a_id, p_id);
    char *ap = strtok(in, " ");
    in = NULL;
    if (!ap || ap[0] == '=') return PI_CLI_STATUS_TOO_FEW_ACTION_PARAMS;

    char bytes[BYTES_TEMP_SIZE];
    if (param_to_bytes(ap, bytes, p_bitwidth)) return 1;
    pi_netv_t p_netv;
    pi_status_t rc;
    rc = pi_getnetv_ptr(p4info_curr, a_id, p_id, bytes, (p_bitwidth + 7) / 8,
                        &p_netv);
    assert(rc == PI_STATUS_SUCCESS);
    rc = pi_action_data_arg_set(adata, &p_netv);
    assert(rc == PI_STATUS_SUCCESS);
  }

  return PI_CLI_STATUS_SUCCESS;
}

void print_action_data(const pi_action_data_t *action_data) {
  pi_p4_id_t action_id = pi_action_data_action_id_get(action_data);

  const char *action_name =
      pi_p4info_action_name_from_id(p4info_curr, action_id);
  printf("Action entry: %s - ", action_name);
  size_t num_params;
  const pi_p4_id_t *param_ids =
      pi_p4info_action_get_params(p4info_curr, action_id, &num_params);
  for (size_t j = 0; j < num_params; j++) {
    pi_netv_t argv;
    pi_action_data_arg_get(action_data, param_ids[j], &argv);
    print_hexstr(argv.v.ptr, argv.size);

    if (j != num_params - 1) printf(", ");
  }
  printf("\n");
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
