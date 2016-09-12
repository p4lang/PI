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

#ifndef PI_CLI_TABLE_COMMON_H_
#define PI_CLI_TABLE_COMMON_H_

#include "error_codes.h"

#include "PI/pi.h"

extern const pi_p4info_t *p4info_curr;
extern pi_dev_tgt_t dev_tgt;
extern pi_session_handle_t sess;

pi_cli_status_t read_action_data(char *in, pi_p4_id_t a_id,
                                 pi_action_data_t *adata);

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
