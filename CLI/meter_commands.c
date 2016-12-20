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
#include <PI/pi_meter.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const pi_p4info_t *p4info_curr;
extern pi_dev_tgt_t dev_tgt;
extern pi_session_handle_t sess;

#define NEXT_ENTRY_TOKEN "NEXT_ENTRY"

static char *complete_meter(const char *text, int state) {
  return complete_one_name(text, state, PI_METER_ID);
}

static const char *meter_unit_to_string(pi_meter_unit_t unit) {
  switch (unit) {
    case PI_METER_UNIT_DEFAULT:
      return "p4-specified";
    case PI_METER_UNIT_PACKETS:
      return "packets";
    case PI_METER_UNIT_BYTES:
      return "bytes";
    default:
      return "unknown";
  }
}

static const char *meter_type_to_string(pi_meter_type_t type) {
  switch (type) {
    case PI_METER_TYPE_DEFAULT:
      return "p4-specified";
    case PI_METER_TYPE_COLOR_AWARE:
      return "color aware";
    case PI_METER_TYPE_COLOR_UNAWARE:
      return "color unaware";
    default:
      return "unknown";
  }
}

static void print_meter_spec(const pi_meter_spec_t *meter_spec) {
  printf("Dumping meter spec:\n");
  printf("\tMeter unit: %s\n", meter_unit_to_string(meter_spec->meter_unit));
  printf("\tMeter type: %s\n", meter_type_to_string(meter_spec->meter_type));
  printf("\tCommitted information rate: %" PRIu64 "\n", meter_spec->cir);
  printf("\tCommitted burst size: %u\n", meter_spec->cburst);
  printf("\tPeak information rate: %" PRIu64 "\n", meter_spec->pir);
  printf("\tPeak burst size: %u\n", meter_spec->pburst);
}

#define REQUIRED_RATES 2
// return 0 if success, 1 if bad format
static int parse_meter_spec(pi_p4_id_t m_id, pi_meter_spec_t *meter_spec) {
  // I was letting the PI code handles this, but it results in an error for
  // direct meters.
  /* meter_spec->meter_unit = PI_METER_UNIT_DEFAULT; */
  /* meter_spec->meter_type = PI_METER_TYPE_DEFAULT; */
  meter_spec->meter_unit =
      (pi_meter_unit_t)pi_p4info_meter_get_unit(p4info_curr, m_id);
  meter_spec->meter_type =
      (pi_meter_type_t)pi_p4info_meter_get_type(p4info_curr, m_id);
  typedef struct {
    uint64_t r;
    uint32_t b;
  } rate_t;
  rate_t rates[REQUIRED_RATES];
  size_t num_rates = 0;

  char *config_str = NULL;
  while (1) {
    config_str = strtok(NULL, " ");
    if (!config_str) break;
    if (num_rates > REQUIRED_RATES) {
      printf("Too many rates provided\n");
      return 1;
    }
    char *sep = strchr(config_str, ':');
    if (!sep) {
      printf("Invalid rate config\n");
      return 1;
    }
    *sep = '\0';
    char *r_str = config_str;  // info rate str
    char *b_str = sep + 1;     // burst size str

    char *endptr;
    rates[num_rates].r = strtoll(r_str, &endptr, 0);
    if (*endptr != '\0') {
      printf("Invalid rate config\n");
      return 1;
    }
    rates[num_rates].b = strtol(b_str, &endptr, 0);
    if (*endptr != '\0') {
      printf("Invalid rate config\n");
      return 1;
    }

    num_rates++;
  }

  if (num_rates != REQUIRED_RATES) {
    printf("Not enough rates provided\n");
    return 1;
  }

  meter_spec->cir = rates[0].r;
  meter_spec->cburst = rates[0].b;
  meter_spec->pir = rates[1].r;
  meter_spec->pburst = rates[1].b;

  return 0;
}
#undef REQUIRED_RATES

static pi_cli_status_t parse_common(char *subcmd, pi_p4_id_t *m_id,
                                    uint64_t *handle, int *for_next_t_entry) {
  const char *args[2];
  size_t num_args = sizeof(args) / sizeof(char *);
  if (parse_fixed_args(subcmd, args, num_args) < num_args)
    return PI_CLI_STATUS_TOO_FEW_ARGS;
  const char *c_name = args[0];
  const char *handle_str = args[1];
  *m_id = pi_p4info_meter_id_from_name(p4info_curr, c_name);
  if (*m_id == PI_INVALID_ID) return PI_CLI_STATUS_INVALID_METER_NAME;
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

char meter_read_spec_hs[] =
    "Read meter spec: "
    "meter_read_spec <meter name> <index | entry handle>";

pi_cli_status_t do_meter_read_spec(char *subcmd) {
  pi_p4_id_t m_id;
  uint64_t handle;
  pi_cli_status_t status;
  status = parse_common(subcmd, &m_id, &handle, NULL);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  pi_p4_id_t direct_t_id = pi_p4info_meter_get_direct(p4info_curr, m_id);
  pi_status_t rc;
  pi_meter_spec_t meter_spec;
  if (direct_t_id == PI_INVALID_ID) {
    size_t index = handle;
    rc = pi_meter_read(sess, dev_tgt, m_id, index, &meter_spec);
  } else {
    pi_entry_handle_t entry_handle = handle;
    rc = pi_meter_read_direct(sess, dev_tgt, m_id, entry_handle, &meter_spec);
  }
  if (rc != PI_STATUS_SUCCESS) {
    printf("Error when trying to read meter spec\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }

  print_meter_spec(&meter_spec);

  return PI_CLI_STATUS_SUCCESS;
}

char *complete_meter_read_spec(const char *text, int state) {
  return complete_meter(text, state);
}

char meter_set_hs[] =
    "Set meter spec: "
    "meter_set <meter name> <index | entry handle> "
    "<rate_1>:<burst_1> <rate_2>:<burst_2>";

static pi_cli_status_t store_direct_meter_config(
    pi_p4_id_t m_id, const pi_meter_spec_t *meter_spec) {
  pi_p4_id_t direct_t_id = pi_p4info_meter_get_direct(p4info_curr, m_id);
  if (direct_t_id == PI_INVALID_ID) {
    printf("Cannot hold resource spec with " NEXT_ENTRY_TOKEN
           " for none-direct resources.\n");
    return PI_CLI_STATUS_ERROR;
  }
  pi_meter_spec_t *meter_spec_copy = malloc(sizeof(*meter_spec));
  memcpy(meter_spec_copy, meter_spec, sizeof(*meter_spec));
  store_direct_resource_config(m_id, meter_spec_copy);
  return PI_CLI_STATUS_SUCCESS;
}

pi_cli_status_t do_meter_set(char *subcmd) {
  pi_p4_id_t m_id;
  uint64_t handle;
  pi_cli_status_t status;
  int for_next_t_entry = 0;
  status = parse_common(subcmd, &m_id, &handle, &for_next_t_entry);
  if (status != PI_CLI_STATUS_SUCCESS) return status;

  pi_meter_spec_t meter_spec;
  if (parse_meter_spec(m_id, &meter_spec))
    return PI_CLI_STATUS_INVALID_COMMAND_FORMAT;
  print_meter_spec(&meter_spec);

  if (for_next_t_entry) {
    status = store_direct_meter_config(m_id, &meter_spec);
    if (status != PI_CLI_STATUS_SUCCESS) return status;
    printf("Direct resource spec was stored.\n");
    return PI_CLI_STATUS_SUCCESS;
  }

  pi_p4_id_t direct_t_id = pi_p4info_meter_get_direct(p4info_curr, m_id);
  pi_status_t rc;
  if (direct_t_id == PI_INVALID_ID) {
    size_t index = handle;
    rc = pi_meter_set(sess, dev_tgt, m_id, index, &meter_spec);
  } else {
    pi_entry_handle_t entry_handle = handle;
    rc = pi_meter_set_direct(sess, dev_tgt, m_id, entry_handle, &meter_spec);
  }
  if (rc != PI_STATUS_SUCCESS) {
    printf("Error when trying to set meter spec\n");
    return PI_CLI_STATUS_TARGET_ERROR;
  }

  return PI_CLI_STATUS_SUCCESS;
}

char *complete_meter_set(const char *text, int state) {
  return complete_meter(text, state);
}
