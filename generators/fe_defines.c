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

#include "PI/p4info.h"
#include "read_file.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void print_help() {
  fprintf(stderr,
          "Usage: pi_gen_fe_defines [OPTIONS]...\n"
          "Generate preprocessor #define's from P4 config\n\n"
          "-c          path to P4 config\n"
          "-d          path to destination dir (where .h will be generated)\n"
          "-n          P4 name to use (for generated fname and prefix)\n");
}

static char *config_path = NULL;
static char *dest_dir = NULL;
static char *p4_name = NULL;

static int parse_opts(int argc, char *const argv[]) {
  int c;

  opterr = 0;

  while ((c = getopt(argc, argv, "c:d:n:h")) != -1) {
    switch (c) {
      case 'c':
        config_path = optarg;
        break;
      case 'd':
        dest_dir = optarg;
        break;
      case 'h':
        print_help();
        exit(0);
      case 'n':
        p4_name = optarg;
        break;
      case '?':
        if (optopt == 'c' || optopt == 'd' || optopt == 'n') {
          fprintf(stderr, "Option -%c requires an argument.\n\n", optopt);
          print_help();
        } else if (isprint(optopt)) {
          fprintf(stderr, "Unknown option `-%c'.\n\n", optopt);
          print_help();
        } else {
          fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
          print_help();
        }
        return 1;
      default:
        abort();
    }
  }

  if (!config_path || !dest_dir || !p4_name) {
    fprintf(stderr, "Options -c, -d and -n are ALL required.\n\n");
    print_help();
    return 1;
  }

  return 0;
}

static void to_upper(char *s) {
  for (; *s != '\0'; s++) *s = toupper(*s);
}

static void sanitize_name(char *s) {
  char *valid_before = "$valid$";
  char *valid_after = "valid";
  char *valid_found = NULL;

  while ((valid_found = strstr(s, valid_before)) != NULL) {
    // overwrite $valid$ with valid, leave out '/0'
    memcpy(valid_found, valid_after, strlen(valid_after));

    // move over rest of string
    char *src = &valid_found[strlen(valid_before)];
    char *dest = &valid_found[strlen(valid_after)];
    memmove(dest, src, strlen(src) + 1);
  }

  for (; *s != '\0'; s++) {
    *s = toupper(*s);
    if (*s == '.' || *s == ']' || *s == '[') *s = '_';
  }
}

static const char prelude[] =
    "/* This file was auto-generated, do not edit !!!\n"
    " */\n\n";

int main(int argc, char *const argv[]) {
  int rc;
  if ((rc = parse_opts(argc, argv)) != 0) return rc;

  char *config = read_file(config_path);
  if (!config) {
    fprintf(stderr, "File '%s' does not exist or cannot be accessed.\n",
            config_path);
    return 1;
  }

  struct stat info;
  if (stat(dest_dir, &info) != 0) {
    fprintf(stderr, "Cannot access '%s'.\n", dest_dir);
    return 1;
  } else if (!(info.st_mode & S_IFDIR)) {
    // S_ISDIR() may not exist on windows
    fprintf(stderr, "'%s' is not a directory.\n", dest_dir);
    return 1;
  }

  char fname[256];
  if (strnlen(p4_name, sizeof(fname)) + strlen("pi_fe_defines_") +
          strlen(".h") >=
      sizeof(fname)) {
    fprintf(stderr, "Provided P4 name (with -n) is too long.\n");
    return 1;
  }
  sprintf(fname, "pi_fe_defines_%s.h", p4_name);

  char gen_path[512];
  if (strnlen(dest_dir, sizeof(gen_path)) + strlen("/") + strlen(fname) >=
      sizeof(gen_path)) {
    fprintf(stderr, "Full path of generated file is too long.\n");
    return 1;
  }
  sprintf(gen_path, "%s/%s", dest_dir, fname);

  printf("Generating header file '%s' ...\n", gen_path);

  FILE *gen_fptr = fopen(gen_path, "w");
  if (!gen_fptr) {
    fprintf(stderr, "Unexpected error when opening file.\n");
    return 1;
  }

  pi_status_t status;
  pi_p4info_t *p4info;
  status = pi_add_config(config, PI_CONFIG_TYPE_BMV2_JSON, &p4info);
  if (status != PI_STATUS_SUCCESS) {
    fprintf(stderr, "Error while loading config.\n");
    return 1;
  }

  fprintf(gen_fptr, prelude);

  char inc_guard[384];
  // static assert
  assert(sizeof(inc_guard) >= sizeof(fname) + 128);
  sprintf(inc_guard, "__AUTOGEN_PI_FE_DEFINES_%s_H_", p4_name);
  to_upper(inc_guard);

  fprintf(gen_fptr, "#ifndef %s\n", inc_guard);
  fprintf(gen_fptr, "#define %s\n\n", inc_guard);

  char prefix[384];
  // static assert
  assert(sizeof(prefix) >= sizeof(fname) + 128);
  sprintf(prefix, "PI_%s", p4_name);
  to_upper(prefix);

  fprintf(gen_fptr, "// ACTIONS AND ACTION PARAMETERS\n\n");
  for (pi_p4_id_t id = pi_p4info_action_begin(p4info);
       id != pi_p4info_action_end(p4info);
       id = pi_p4info_action_next(p4info, id)) {
    const char *name = pi_p4info_action_name_from_id(p4info, id);
    // quick and dirty
    char *name_ = strdup(name);
    sanitize_name(name_);
    fprintf(gen_fptr, "#define %s_ACTION_%s %#x\n", prefix, name_, id);
    size_t num_params = 0;
    const pi_p4_id_t *params =
        pi_p4info_action_get_params(p4info, id, &num_params);
    for (size_t i = 0; i < num_params; i++) {
      pi_p4_id_t p_id = params[i];
      const char *p_name =
          pi_p4info_action_param_name_from_id(p4info, id, p_id);
      char *p_name_ = strdup(p_name);
      sanitize_name(p_name_);
      fprintf(gen_fptr, "#define %s_ACTIONP_%s_%s %#x\n", prefix, name_,
              p_name_, p_id);
      free(p_name_);
    }
    free(name_);
    fprintf(gen_fptr, "\n");
  }
  fprintf(gen_fptr, "\n");

  fprintf(gen_fptr, "// ACTIONS PROFILES\n\n");
  for (pi_p4_id_t id = pi_p4info_act_prof_begin(p4info);
       id != pi_p4info_act_prof_end(p4info);
       id = pi_p4info_act_prof_next(p4info, id)) {
    const char *name = pi_p4info_act_prof_name_from_id(p4info, id);
    // quick and dirty
    char *name_ = strdup(name);
    sanitize_name(name_);
    fprintf(gen_fptr, "#define %s_ACT_PROF_%s %#x\n", prefix, name_, id);
    free(name_);
    fprintf(gen_fptr, "\n");
  }
  fprintf(gen_fptr, "\n");

  fprintf(gen_fptr, "// TABLES AND MATCH FIELDS\n\n");
  for (pi_p4_id_t id = pi_p4info_table_begin(p4info);
       id != pi_p4info_table_end(p4info);
       id = pi_p4info_table_next(p4info, id)) {
    const char *name = pi_p4info_table_name_from_id(p4info, id);
    // quick and dirty
    char *name_ = strdup(name);
    sanitize_name(name_);
    fprintf(gen_fptr, "#define %s_TABLE_%s %#x\n", prefix, name_, id);
    size_t num_match_fields = 0;
    const pi_p4_id_t *match_fields =
        pi_p4info_table_get_match_fields(p4info, id, &num_match_fields);
    for (size_t i = 0; i < num_match_fields; i++) {
      pi_p4_id_t mf_id = match_fields[i];
      const char *mf_name =
          pi_p4info_table_match_field_name_from_id(p4info, id, mf_id);
      char *mf_name_ = strdup(mf_name);
      sanitize_name(mf_name_);
      fprintf(gen_fptr, "#define %s_MF_%s_%s %#x\n", prefix, name_, mf_name_,
              mf_id);
      free(mf_name_);
    }
    free(name_);
    fprintf(gen_fptr, "\n");
  }
  fprintf(gen_fptr, "\n");

  fprintf(gen_fptr, "#endif  // %s\n", inc_guard);

  free(config);
  pi_destroy_config(p4info);
  fclose(gen_fptr);
}
