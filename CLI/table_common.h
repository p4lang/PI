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

#ifndef PI_CLI_TABLE_COMMON_H_
#define PI_CLI_TABLE_COMMON_H_

#include "error_codes.h"

#include "PI/pi.h"

extern const pi_p4info_t *p4info_curr;
extern pi_dev_tgt_t dev_tgt;
extern pi_session_handle_t sess;

pi_cli_status_t read_match_fields(char *in, pi_p4_id_t t_id,
                                  pi_match_key_t *mk);

pi_cli_status_t read_match_key_with_priority(char *in, pi_p4_id_t t_id,
                                             pi_match_key_t *mk,
                                             const char *end);

pi_cli_status_t read_action_data(char *in, pi_p4_id_t a_id,
                                 pi_action_data_t *adata);

void print_action_data(const pi_action_data_t *action_data);

char *complete_table(const char *text, int state);
char *complete_table_and_action(const char *text, int state);

pi_cli_status_t get_entry_direct(pi_table_entry_t *t_entry);
pi_cli_status_t get_entry_indirect(pi_table_entry_t *t_entry);
void cleanup_entry_direct(pi_table_entry_t *t_entry);
void cleanup_entry_indirect(pi_table_entry_t *t_entry);

// takes ownership of config
void store_direct_resource_config(pi_p4_id_t res_id, void *config);
pi_direct_res_config_one_t *retrieve_direct_resource_configs(
    size_t *num_configs);
void reset_direct_resource_configs();

#endif  // PI_CLI_TABLE_COMMON_H_
