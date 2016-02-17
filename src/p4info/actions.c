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

#include "PI/p4info/actions.h"
#include "p4info/p4info_struct.h"

#include <stdlib.h>

#define INLINE_PARAMS 8

typedef struct {
  const char *name;
  size_t bitwidth;
} _action_param_data_t;

typedef struct _action_data_s {
  const char *name;
  size_t num_params;
  union {
    pi_p4_id_t direct[INLINE_PARAMS];
    pi_p4_id_t *indirect;
  } param_ids;
  union {
    _action_param_data_t direct[INLINE_PARAMS];
    _action_param_data_t *indirect;
  } param_data;
} _action_data_t;

void pi_p4info_action_init(pi_p4info_t *p4info, size_t num_actions) {
  p4info->num_actions = num_actions;
  p4info->actions = malloc(sizeof(_action_data_t) * num_actions);
}

void pi_p4info_action_add(pi_p4info_t *p4info, pi_p4_id_t action_id,
                          const char *name, size_t num_params) {
  (void) p4info; (void) action_id; (void) name; (void) num_params;
}

void pi_p4info_action_add_param(pi_p4info_t *p4info, pi_p4_id_t action_id,
                                pi_p4_id_t param_id, const char *name,
                                size_t bitwidth) {
  (void) p4info;
  (void) action_id; (void) param_id; (void) name; (void) bitwidth;
}

pi_p4_id_t pi_p4info_action_id_from_name(const pi_p4info_t *p4info,
                                         const char *name) {
  (void) p4info; (void) p4info; (void) name;
  return 0;
}

const char *pi_p4info_action_name_from_id(const pi_p4info_t *p4info,
                                          pi_p4_id_t action_id) {
  (void) p4info; (void) action_id;
  return NULL;
}

size_t pi_p4info_action_num_params(const pi_p4info_t *p4info,
                                   pi_p4_id_t action_id) {
  (void) p4info; (void) action_id;
  return 0;
}

const pi_p4_id_t *pi_p4info_action_get_params(const pi_p4info_t *p4info,
                                              pi_p4_id_t action_id,
                                              size_t *num_params) {
  (void) p4info; (void) action_id; (void) num_params;
  return NULL;
}

pi_p4_id_t pi_p4info_action_param_id_from_name(const pi_p4info_t *p4info,
                                               const char *name) {
  (void) p4info; (void) name;
  return 0;
}

bool pi_p4info_action_is_param_of(const pi_p4info_t *p4info,
                                  pi_p4_id_t action_id, pi_p4_id_t param_id) {
  (void) p4info; (void) action_id; (void) param_id;
  return false;
}
