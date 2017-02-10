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

void print_hexstr(const char *bytes, size_t nbytes);

#endif  // PI_CLI_UTILS_H_
