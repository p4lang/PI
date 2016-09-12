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

#ifndef PI_CLI_UTILS_H_
#define PI_CLI_UTILS_H_

#include <PI/pi_base.h>

#include <stddef.h>

int count_tokens(const char *str);

// client needs to free memory when done using it
char *get_token_from_buffer(char *buffer, size_t index);

char *complete_p4_table(const char *text, int len, int state);
char *complete_p4_action(const char *text, int len, int state,
                         const char *table);

size_t parse_fixed_args(char *s, const char **dest, size_t expected);

void parse_kv_pair(char *s, char **k, char **v);

int param_to_bytes(const char *param, char *bytes, size_t bitwidth);

char *complete_p4_res(const char *text, int len, int state,
                      pi_res_type_id_t res_type);

// meant to be used when the completion only involves one resource name
char *complete_one_name(const char *text, int state, pi_res_type_id_t res_type);

#endif  // PI_CLI_UTILS_H_
