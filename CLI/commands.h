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

extern char table_delete_wkey_hs[];
pi_cli_status_t do_table_delete_wkey(char *subcmd);
char *complete_table_delete_wkey(const char *text, int state);

extern char table_modify_hs[];
pi_cli_status_t do_table_modify(char *subcmd);
char *complete_table_modify(const char *text, int state);

extern char table_modify_wkey_hs[];
pi_cli_status_t do_table_modify_wkey(char *subcmd);
char *complete_table_modify_wkey(const char *text, int state);

extern char table_set_default_hs[];
pi_cli_status_t do_table_set_default(char *subcmd);
char *complete_table_set_default(const char *text, int state);

extern char table_dump_hs[];
pi_cli_status_t do_table_dump(char *subcmd);
char *complete_table_dump(const char *text, int state);

extern char add_p4_hs[];
pi_cli_status_t do_add_p4(char *subcmd);

extern char assign_device_hs[];
pi_cli_status_t do_assign_device(char *subcmd);

extern char select_device_hs[];
pi_cli_status_t do_select_device(char *subcmd);

extern char show_devices_hs[];
pi_cli_status_t do_show_devices(char *subcmd);

extern char remove_device_hs[];
pi_cli_status_t do_remove_device(char *subcmd);

extern char update_device_start_hs[];
pi_cli_status_t do_update_device_start(char *subcmd);

extern char update_device_end_hs[];
pi_cli_status_t do_update_device_end(char *subcmd);

extern char act_prof_create_member_hs[];
pi_cli_status_t do_act_prof_create_member(char *subcmd);
char *complete_act_prof_create_member(const char *text, int state);

extern char act_prof_create_group_hs[];
pi_cli_status_t do_act_prof_create_group(char *subcmd);
char *complete_act_prof_create_group(const char *text, int state);

extern char act_prof_add_member_to_group_hs[];
pi_cli_status_t do_act_prof_add_member_to_group(char *subcmd);
char *complete_act_prof_add_member_to_group(const char *text, int state);

extern char act_prof_dump_hs[];
pi_cli_status_t do_act_prof_dump(char *subcmd);
char *complete_act_prof_dump(const char *text, int state);

extern char counter_read_hs[];
pi_cli_status_t do_counter_read(char *subcmd);
char *complete_counter_read(const char *text, int state);

extern char counter_write_hs[];
pi_cli_status_t do_counter_write(char *subcmd);
char *complete_counter_write(const char *text, int state);

extern char counter_reset_hs[];
pi_cli_status_t do_counter_reset(char *subcmd);
char *complete_counter_reset(const char *text, int state);

extern char meter_read_spec_hs[];
pi_cli_status_t do_meter_read_spec(char *subcmd);
char *complete_meter_read_spec(const char *text, int state);

extern char meter_set_hs[];
pi_cli_status_t do_meter_set(char *subcmd);
char *complete_meter_set(const char *text, int state);

extern char direct_res_reset_hs[];
pi_cli_status_t do_direct_res_reset(char *subcmd);

#endif  // PI_CLI_COMMANDS_H_
