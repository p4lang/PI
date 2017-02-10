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

#include "commands.h"
#include "error_codes.h"
#include "p4_config_repo.h"

#include "PI/pi.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <readline/history.h>
#include <readline/readline.h>

#include <Judy.h>

// this contains the current P4 information (for the selected device)
const pi_p4info_t *p4info_curr = NULL;

pi_dev_tgt_t dev_tgt = {0, 0xffff};
int is_device_selected = 0;
pi_session_handle_t sess;

// command-line options
static char *opt_config_path = NULL;
static char *opt_rpc_addr = NULL;
static char *opt_notifications_addr = NULL;
static int opt_call_pi_destroy = 0;

typedef pi_cli_status_t (*CLIFnPtr)(char *);
typedef char *(*CLICompPtr)(const char *text, int state);

#define PI_CLI_CMD_FLAGS_REQUIRES_DEVICE (1 << 0)

typedef struct {
  const char *name;
  CLIFnPtr fn_ptr;
  const char *help_str;
  CLICompPtr comp_ptr;
  int flags;
} cmd_data_t;

static Pvoid_t J_cmd_name_map = (Pvoid_t)NULL;
static cmd_data_t cmd_map[1024];
static size_t num_cmds = 0u;

static cmd_data_t *get_cmd_data(const char *cmd_name) {
  Word_t *cmd_data_ptr = NULL;
  JSLG(cmd_data_ptr, J_cmd_name_map, (const uint8_t *)cmd_name);
  if (!cmd_data_ptr) return NULL;
  return (cmd_data_t *)(*cmd_data_ptr);
}

typedef void (*CbFn)(const cmd_data_t *cmd_data, void *);

static void foreach_cmd(CbFn cb, void *cookie) {
  for (size_t i = 0; i < num_cmds; i++) {
    const cmd_data_t *cmd_data = &cmd_map[i];
    cb(cmd_data, cookie);
  }
}

static void print_cmd_desc(const cmd_data_t *cmd_data, void *cookie) {
  (void)cookie;
  printf("%-20s %s\n", cmd_data->name, cmd_data->help_str);
}

// TODO(unknown): find max length of command by looping over them and adjust
// column-width based on the result
static pi_cli_status_t do_help(char *subcmd) {
  if (subcmd) {
    char *c = strtok(subcmd, " ");
    if (c) {
      cmd_data_t *cmd_data = get_cmd_data(c);
      if (cmd_data && !cmd_data->help_str) return PI_CLI_STATUS_SUCCESS;
      ;
      if (cmd_data && cmd_data->help_str) {
        printf("%-20s %s\n", subcmd, cmd_data->help_str);
        return PI_CLI_STATUS_SUCCESS;
      }
      fprintf(stderr, "Unknown command name '%s'.\n", c);
    }
  }
  printf("%-20s %s\n", "commands", "description");
  printf("\n");
  foreach_cmd(print_cmd_desc, NULL);
  return PI_CLI_STATUS_SUCCESS;
}

char *command_generator(const char *text, int state);

// re-using command_generator, coz I'm smart and lazy
static char *complete_help(const char *text, int state) {
  return command_generator(text, state);
}

static void register_cmd(const char *name, CLIFnPtr fn, const char *help_str,
                         CLICompPtr comp, int flags) {
  cmd_data_t *cmd_data = &cmd_map[num_cmds];
  cmd_data->name = name;
  cmd_data->fn_ptr = fn;
  cmd_data->help_str = help_str;
  cmd_data->comp_ptr = comp;
  cmd_data->flags = flags;
  Word_t *cmd_data_ptr;
  JSLI(cmd_data_ptr, J_cmd_name_map, (const uint8_t *)name);
  *cmd_data_ptr = (Word_t)cmd_data;
  num_cmds++;
}

static void init_cmd_map() {
  register_cmd("quit", NULL, "Exits CLI", NULL, 0);
  register_cmd("help", do_help, "Print this message", complete_help, 0);

  register_cmd("add_p4", do_add_p4, add_p4_hs, NULL, 0);
  register_cmd("assign_device", do_assign_device, assign_device_hs, NULL, 0);
  register_cmd("select_device", do_select_device, select_device_hs, NULL, 0);
  register_cmd("remove_device", do_remove_device, remove_device_hs, NULL, 0);
  register_cmd("show_devices", do_show_devices, show_devices_hs, NULL, 0);

  register_cmd("update_device_start", do_update_device_start,
               update_device_start_hs, NULL, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("update_device_end", do_update_device_end, update_device_end_hs,
               NULL, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);

  register_cmd("table_add", do_table_add, table_add_hs, complete_table_add,
               PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("table_delete", do_table_delete, table_delete_hs,
               complete_table_delete, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("table_delete_wkey", do_table_delete_wkey, table_delete_wkey_hs,
               complete_table_delete_wkey, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("table_modify", do_table_modify, table_modify_hs,
               complete_table_modify, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("table_modify_wkey", do_table_modify_wkey, table_modify_wkey_hs,
               complete_table_modify_wkey, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("table_set_default", do_table_set_default, table_set_default_hs,
               complete_table_set_default, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("table_dump", do_table_dump, table_dump_hs, complete_table_dump,
               PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);

  register_cmd("act_prof_create_member", do_act_prof_create_member,
               act_prof_create_member_hs, complete_act_prof_create_member,
               PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("act_prof_create_group", do_act_prof_create_group,
               act_prof_create_group_hs, complete_act_prof_create_group,
               PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("act_prof_add_member_to_group", do_act_prof_add_member_to_group,
               act_prof_add_member_to_group_hs,
               complete_act_prof_add_member_to_group,
               PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("act_prof_dump", do_act_prof_dump, act_prof_dump_hs,
               complete_act_prof_dump, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);

  register_cmd("counter_read", do_counter_read, counter_read_hs,
               complete_counter_read, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("counter_write", do_counter_write, counter_write_hs,
               complete_counter_write, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("counter_reset", do_counter_reset, counter_reset_hs,
               complete_counter_reset, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);

  register_cmd("meter_read_spec", do_meter_read_spec, meter_read_spec_hs,
               complete_meter_read_spec, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("meter_set", do_meter_set, meter_set_hs, complete_meter_set,
               PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);

  register_cmd("direct_res_reset", do_direct_res_reset, direct_res_reset_hs,
               NULL, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
}

static void cleanup() {
  Word_t bytes;
// there is code in Judy headers that raises a warning with some compiler
// versions
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wsign-compare"
  JSLFA(bytes, J_cmd_name_map);
#pragma GCC diagnostic pop

  if (is_device_selected) pi_remove_device(dev_tgt.dev_id);

  // will cleanup current config as well
  p4_config_cleanup();

  pi_session_cleanup(sess);

  if (opt_call_pi_destroy) pi_destroy();
}

static void dispatch_command(const char *first_word, char *subcmd) {
  assert(first_word);
  const cmd_data_t *cmd_data = get_cmd_data(first_word);
  if (cmd_data) {
    if ((cmd_data->flags & PI_CLI_CMD_FLAGS_REQUIRES_DEVICE) &&
        !is_device_selected) {
      fprintf(stderr,
              "Cannot execute this command without selecting a device "
              "first with the 'select_device' command.\n");
      return;
    }
    pi_cli_status_t status = cmd_data->fn_ptr(subcmd);
    if (status != PI_CLI_STATUS_SUCCESS) {
      fprintf(stderr, "Command returned with the following error:\n");
      fprintf(stderr, "%s\n", error_code_to_string(status));
    }
  } else {
    fprintf(stderr, "Unknown command '%s'\n", first_word);
  }
}

// returns 0 if wants loop to continue, <> 0 otherwise
static int process_one_cmd(char *cmd) {
  if (!cmd) return 1;
  if (!strcmp("quit", cmd)) return 1;
  if (cmd[0] == '\0') return 0;
  add_history(cmd);
  char *token = NULL;
  for (token = cmd; (*token != '\0') && (*token != ' '); token++)
    ;
  char *subcmd = NULL;
  if (token[0] != '\0') {
    subcmd = token + 1;
    *token = '\0';
  }

  dispatch_command(cmd, subcmd);
  return 0;
}

char *command_generator(const char *text, int state) {
  static size_t index;
  static int len;

  /* If this is a new word to complete, initialize now.  This includes
     saving the length of TEXT for efficiency, and initializing the index
     variable to 0. */
  if (!state) {
    index = 0u;
    len = strlen(text);
  }

  while (index < num_cmds) {
    const cmd_data_t *cmd_data = &cmd_map[index];
    index++;  // needs to be increased before returning or infinite loop!!!
    if (!strncmp(cmd_data->name, text, len)) return strdup(cmd_data->name);
  }

  return NULL;
}

/* Attempt to complete on the contents of TEXT.  START and END show the region
of TEXT that contains the word to complete.  We can use the entire line in case
we want to do some simple parsing.  Return the array of matches, or NULL if
there aren't any. */
char **CLI_completion(const char *text, int start, int end) {
  (void)end;

  char **matches = NULL;

  // If this word is at the start of the line, then it is a command to complete.
  if (start == 0) {
    matches = rl_completion_matches(text, command_generator);
  } else {
    // my solution to retrieve the command name and do a dispatch to the
    // command-specific completion function
    char *e = strchr(rl_line_buffer, ' ');
    char saved_e = *e;
    *e = '\0';
    cmd_data_t *cmd_data = get_cmd_data(rl_line_buffer);
    *e = saved_e;
    if (cmd_data && cmd_data->comp_ptr) {
      if (!(cmd_data->flags & PI_CLI_CMD_FLAGS_REQUIRES_DEVICE) ||
          is_device_selected) {
        matches = rl_completion_matches(text, cmd_data->comp_ptr);
      }
    }
  }

  return matches;
}

// We assign this function to rl_completion_entry_function. According to the
// readline documentation
// (http://www.delorie.com/gnu/docs/readline/rlman_47.html), this variable is a
// function pointer of type rl_compentry_func_t. Again according to the
// documentation (http://www.delorie.com/gnu/docs/readline/rlman_26.html), the
// return type should be char *. However, it seems that for macos, the expected
// return type is int.
#ifdef __APPLE__
int dummy_completion(const char *text, int state) {
  (void)text;
  (void)state;
  return 0;
}
#else
char *dummy_completion(const char *text, int state) {
  (void)text;
  (void)state;
  return NULL;
}
#endif

static void print_help(const char *name) {
  fprintf(stderr,
          "Usage: %s [OPTIONS]...\n"
          "PI CLI\n\n"
          "-c          path to P4 bmv2 JSON config\n"
          "-a          nanomsg address, for RPC mode\n"
          "-d          call pi_destroy when done\n",
          name);
}

static int parse_opts(int argc, char *const argv[]) {
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "c:a:n:dh")) != -1) {
    switch (c) {
      case 'c':
        opt_config_path = optarg;
        break;
      case 'a':
        opt_rpc_addr = optarg;
        break;
      case 'n':
        opt_notifications_addr = optarg;
        break;
      case 'd':
        opt_call_pi_destroy = 1;
        break;
      case 'h':
        print_help(argv[0]);
        exit(0);
      case '?':
        if (optopt == 'c' || optopt == 'a') {
          fprintf(stderr, "Option -%c requires an argument.\n\n", optopt);
          print_help(argv[0]);
        } else if (isprint(optopt)) {
          fprintf(stderr, "Unknown option `-%c'.\n\n", optopt);
          print_help(argv[0]);
        } else {
          fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
          print_help(argv[0]);
        }
        return 1;
      default:
        abort();
    }
  }

  int extra_arg = 0;
  for (int index = optind; index < argc; index++) {
    fprintf(stderr, "Non-option argument: %s\n", argv[index]);
    extra_arg = 1;
  }
  if (extra_arg) {
    print_help(argv[0]);
    return 1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  if (parse_opts(argc, argv) != 0) return 1;

  pi_status_t pirc;
  pi_remote_addr_t remote_addr = {opt_rpc_addr, opt_notifications_addr};
  pi_init(256, &remote_addr);  // 256 devices max

  if (opt_config_path) {
    pi_p4info_t *p4info;
    pirc = pi_add_config_from_file(opt_config_path, PI_CONFIG_TYPE_BMV2_JSON,
                                   &p4info);
    if (pirc != PI_STATUS_SUCCESS) {
      fprintf(stderr, "Error while loading config\n");
      return 1;
    }
    p4_config_id_t p4_config_id = p4_config_add(p4info);
    (void)p4_config_id;
  }

  pirc = pi_session_init(&sess);
  if (pirc != PI_STATUS_SUCCESS) {
    fprintf(stderr, "Error while opening PI client session\n");
    return 1;
  }

  init_cmd_map();

  rl_attempted_completion_function = CLI_completion;
  // this effectively disables filename completion
  rl_completion_entry_function = dummy_completion;

  int rc;
  while (1) {
    char *cmd = readline("PI CLI> ");
    rc = process_one_cmd(cmd);
    free(cmd);
    if (rc) break;
  }

  cleanup();
}
