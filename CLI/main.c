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

#include "commands.h"
#include "error_codes.h"

#include "PI/pi.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <Judy.h>

// this contains all the needed P4 information
pi_p4info_t *p4info = NULL;

pi_dev_tgt_t dev_tgt = {0, 0xffff};
int is_device_attached = 0;

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

static Pvoid_t J_cmd_name_map = (Pvoid_t) NULL;
static cmd_data_t cmd_map[1024];
static size_t num_cmds = 0u;

static cmd_data_t *get_cmd_data(const char *cmd_name) {
  Word_t *cmd_data_ptr = NULL;
  JSLG(cmd_data_ptr, J_cmd_name_map, (const uint8_t *) cmd_name);
  if (!cmd_data_ptr) return NULL;
  return (cmd_data_t *) (*cmd_data_ptr);
}

typedef void (*CbFn)(const cmd_data_t *cmd_data, void *);

static void foreach_cmd(CbFn cb, void *cookie) {
  for (size_t i = 0; i < num_cmds; i++) {
    const cmd_data_t *cmd_data = &cmd_map[i];
    cb(cmd_data, cookie);
  }
}

static void print_cmd_desc(const cmd_data_t *cmd_data, void *cookie) {
  (void) cookie;
  printf("%-20s %s\n", cmd_data->name, cmd_data->help_str);
}

// TODO(unknown): find max length of command by looping over them and adjust
// column-width based on the result
static pi_cli_status_t do_help(char *subcmd) {
  if (subcmd) {
    char *c = strtok(subcmd, " ");
    if (c) {
      cmd_data_t *cmd_data = get_cmd_data(c);
      if (cmd_data && !cmd_data->help_str) return PI_CLI_STATUS_SUCCESS;;
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

char* command_generator(const char* text, int state);

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
  JSLI(cmd_data_ptr, J_cmd_name_map, (const uint8_t *) name);
  *cmd_data_ptr = (Word_t) cmd_data;
  num_cmds++;
}

static void init_cmd_map() {
  register_cmd("quit", NULL, "Exits CLI", NULL, 0);
  register_cmd("help", do_help, "Print this message", complete_help, 0);
  register_cmd("select_device", do_select_device, select_device_hs, NULL, 0);
  register_cmd("table_add", do_table_add, table_add_hs, complete_table_add,
               PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
  register_cmd("table_delete", do_table_delete, table_delete_hs,
               complete_table_delete, PI_CLI_CMD_FLAGS_REQUIRES_DEVICE);
}

static void cleanup() {
  Word_t bytes;
  JSLFA(bytes, J_cmd_name_map);

  if (is_device_attached) pi_remove_device(dev_tgt.dev_id);

  pi_destroy_config(p4info);

  pi_destroy();
}

static void dispatch_command(const char *first_word, char *subcmd) {
  assert(first_word);
  const cmd_data_t *cmd_data = get_cmd_data(first_word);
  if (cmd_data) {
    if ((cmd_data->flags & PI_CLI_CMD_FLAGS_REQUIRES_DEVICE) &&
        !is_device_attached) {
      fprintf(stderr, "Cannot execute this command without selecting a device "
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
  for (token = cmd; (*token != '\0') && (*token != ' '); token++);
  char *subcmd = NULL;
  if (token[0] != '\0') {
    subcmd = token + 1;
    *token = '\0';
  }

  dispatch_command(cmd, subcmd);
  return 0;
}

char* command_generator(const char* text, int state) {
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
  (void) end;

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
    if (cmd_data && cmd_data->comp_ptr)
      matches = rl_completion_matches(text, cmd_data->comp_ptr);
  }

  return matches;
}

char *dummy_completion(const char *text, int state) {
  (void) text; (void) state;
  return NULL;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "P4 configuration needed.\n");
    fprintf(stderr, "Usage: %s <path to config>\n", argv[0]);
    return 1;
  }

  pi_status_t pirc;
  pi_init();
  pirc = pi_add_config_from_file(argv[1], PI_CONFIG_TYPE_BMV2_JSON, &p4info);
  if (pirc != PI_STATUS_SUCCESS) {
    fprintf(stderr, "Error while loading config\n");
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
