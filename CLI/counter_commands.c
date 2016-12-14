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

#include "error_codes.h"
#include "table_common.h"  // for holding direct resources
#include "utils.h"

#include <PI/pi.h>
#include <PI/pi_counter.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const pi_p4info_t *p4info_curr;
extern pi_dev_tgt_t dev_tgt;
extern pi_session_handle_t sess;

#define NEXT_ENTRY_TOKEN "NEXT_ENTRY"

static char *complete_counter(const char *text, int state) {
  return complete_one_name(text, state, PI_COUNTER_ID);
}

static void print_counter_data(const pi_counter_data_t *counter_data) {
  printf("Dumping counter entry:\n");
  if (counter_data->valid == 0) {
    printf("\tNo value to dump.\n");
    return;
  }
  if (counter_data->valid & PI_COUNTER_UNIT_PACKETS)
    printf("\tPackets: %" PRIu64 "\n", counter_data->packets);
  if (counter_data->valid & PI_COUNTER_UNIT_BYTES)
    printf("\tBytes: %" PRIu64 "\n", counter_data->bytes);
}

// return 0 if success, 1 if bad format
static int parse_counter_data(pi_counter_data_t *counter_data) {
  memset(counter_data, 0, sizeof(*counter_data));
  char *type_str = NULL;
  char *v_str = NULL;
  while (1) {
    parse_kv_pair(NULL, &type_str, &v_str);
    if (!type_str) break;
    if (!v_str) return 1;
    char *endptr;
    pi_counter_value_t v = strtoll(v_str, &endptr, 0);
    if (*endptr != '\0') return 1;
    if (!strncmp("bytes", type_str, sizeof "bytes")) {
      if (counter_data->valid & PI_COUNTER_UNIT_BYTES) {
        printf("Do not specify same unit type twice\n");
        return 1;
      }
      counter_data->bytes = v;
      counter_data->valid |= PI_COUNTER_UNIT_BYTES;
    } else if (!strncmp("packets", type_str, sizeof "packets")) {
      if (counter_data->valid & PI_COUNTER_UNIT_PACKETS) {
        printf("Do not specify same unit type twice\n");
        return 1;
      }
      counter_data->packets = v;
      counter_data->valid |= PI_COUNTER_UNIT_PACKETS;
    } else {
      printf("Invalid counter unit type '%s'\n", type_str);
    }
  }
  if (counter_data->valid == 0) {
    printf("Please specify at least one value for the counter.\n");
    return 1;
  }
  return 0;
}

// used by counter_write and counter_reset
static pi_status_t write_counter(pi_p4_id_t c_id, uint64_t handle,
                                 const pi_counter_data_t *counter_data) {
  pi_p4_id_t direct_t_id = pi_p4info_counter_get_direct(p4info_curr, c_id);
  pi_status_t rc;
  if (direct_t_id == PI_INVALID_ID) {
    size_t index = handle;
    rc = pi_counter_write(sess, dev_tgt, c_id, index, counter_data);
  } else {
    pi_entry_handle_t entry_handle = handle;
    rc = pi_counter_write_direct(sess, dev_tgt, c_id, entry_handle,
                                 counter_data);
  }
  return rc;
}

static pi_cli_status_t parse_common(char *subcmd, pi_p4_id_t *c_id,
                                    uint64_t *handle, int *for_next_t_entry) {
  const char *args[2];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *c_name = args[0];
  const char *handle_str = args[1];
  *c_id = pi_p4info_counter_id_from_name(p4info_curr, c_name);
  if (*c_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_COUNTER_NAME;
  if (!strncmp(NEXT_ENTRY_TOKEN, handle_str, sizeof NEXT_ENTRY_TOKEN)) {
    if (!for_next_t_entry) {
      printf(NEXT_ENTRY_TOKEN " not valid for this command\n");
      return PI_CLI_STATUS_INVALID_ENTRY_HANDLE;
    }
    *for_next_t_entry = 1;
    return PI_CLI_STATUS_SUCCESS;
  } else if (for_next_t_entry) {
    *for_next_t_entry = 0;
  }
  char *endptr;
  *handle = strtoll(handle_str, &endptr, 0);
  if (*endptr != '\0') return PI_CLI_STATUS_INVALID_ENTRY_HANDLE;
  return PI_CLI_STATUS_SUCCESS;
}

char counter_read_hs[] =
    "Read value(s) from counter: "
    "counter_read <counter name> <index | entry handle>";

pi_cli_status_t do_counter_read(char *subcmd) {
  pi_p4_id_t c_id;
  uint64_t handle;
  pi_cli_status_t status;
  status = parse_common(subcmd, &c_id, &handle, NULL);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  pi_p4_id_t direct_t_id = pi_p4info_counter_get_direct(p4info_curr, c_id);
  pi_status_t rc;
  pi_counter_data_t counter_data;
  int flags = PI_COUNTER_FLAGS_HW_SYNC;
  if (direct_t_id == PI_INVALID_ID) {
    size_t index = handle;
    rc = pi_counter_read(sess, dev_tgt, c_id, index, flags, &counter_data);
  } else {
    pi_entry_handle_t entry_handle = handle;
    rc = pi_counter_read_direct(sess, dev_tgt, c_id, entry_handle, flags,
                                &counter_data);
  }
  if (rc != PI_STATUS_SUCCESS) {
    printf("Error when trying to read counter\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }

  print_counter_data(&counter_data);

  return PI_CLI_STATUS_SUCCESS;
}

char *complete_counter_read(const char *text, int state) {
  return complete_counter(text, state);
}

char counter_write_hs[] =
    "Write value(s) to counter: "
    "counter_write <counter name> <index | entry handle> "
    "[packets=<N>] [bytes=<N>]";

static pi_cli_status_t store_direct_counter_config(
    pi_p4_id_t c_id, const pi_counter_data_t *counter_data) {
  pi_p4_id_t direct_t_id = pi_p4info_counter_get_direct(p4info_curr, c_id);
  if (direct_t_id == PI_INVALID_ID) {
    printf("Cannot hold resource spec with " NEXT_ENTRY_TOKEN
           " for none-direct resources.\n");
    return PI_CLI_STATUS_ERROR;
  }
  pi_counter_data_t *counter_data_copy = malloc(sizeof(*counter_data));
  memcpy(counter_data_copy, counter_data, sizeof(*counter_data));
  store_direct_resource_config(c_id, counter_data_copy);
  return PI_CLI_STATUS_SUCCESS;
}

pi_cli_status_t do_counter_write(char *subcmd) {
  pi_p4_id_t c_id;
  uint64_t handle;
  pi_cli_status_t status;
  int for_next_t_entry = 0;
  status = parse_common(subcmd, &c_id, &handle, &for_next_t_entry);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  pi_counter_data_t counter_data;
  if (parse_counter_data(&counter_data))
    return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  print_counter_data(&counter_data);

  if (for_next_t_entry) {
    status = store_direct_counter_config(c_id, &counter_data);
    if (status != PI_CLI_STATUS_SUCCESS) return status;
    printf("Direct resource spec was stored.\n");
    return PI_CLI_STATUS_SUCCESS;
  }

  pi_status_t rc = write_counter(c_id, handle, &counter_data);
  if (rc != PI_STATUS_SUCCESS) {
    printf("Error when trying to write counter\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }

  return PI_CLI_STATUS_SUCCESS;
}

char *complete_counter_write(const char *text, int state) {
  return complete_counter(text, state);
}

char counter_reset_hs[] =
    "Reset values for counter to 0: "
    "counter_reset <counter name> <index | entry handle>";

pi_cli_status_t do_counter_reset(char *subcmd) {
  pi_p4_id_t c_id;
  uint64_t handle;
  pi_cli_status_t status;
  status = parse_common(subcmd, &c_id, &handle, NULL);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  pi_counter_data_t counter_data;
  counter_data.valid = PI_COUNTER_UNIT_PACKETS | PI_COUNTER_UNIT_BYTES;
  counter_data.bytes = 0;
  counter_data.packets = 0;

  pi_status_t rc = write_counter(c_id, handle, &counter_data);
  if (rc != PI_STATUS_SUCCESS) {
    printf("Error when trying to reset counter\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }

  return PI_CLI_STATUS_SUCCESS;
}

char *complete_counter_reset(const char *text, int state) {
  return complete_counter(text, state);
}
