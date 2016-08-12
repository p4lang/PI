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

#ifndef PI_CLI_COMMANDS_H_
#define PI_CLI_COMMANDS_H_

#include "error_codes.h"

extern char table_add_hs[];
pi_cli_status_t do_table_add(char *subcmd);
char *complete_table_add(const char *text, int state);

extern char table_delete_hs[];
pi_cli_status_t do_table_delete(char *subcmd);
char *complete_table_delete(const char *text, int state);

extern char table_modify_hs[];
pi_cli_status_t do_table_modify(char *subcmd);
char *complete_table_modify(const char *text, int state);

extern char table_set_default_hs[];
pi_cli_status_t do_table_set_default(char *subcmd);
char *complete_table_set_default(const char *text, int state);

extern char table_dump_hs[];
pi_cli_status_t do_table_dump(char *subcmd);
char *complete_table_dump(const char *text, int state);

extern char select_device_hs[];
pi_cli_status_t do_select_device(char *subcmd);

extern char table_indirect_create_member_hs[];
pi_cli_status_t do_table_indirect_create_member(char *subcmd);
char *complete_table_indirect_create_member(const char *text, int state);

#endif  // PI_CLI_COMMANDS_H_
