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
#include "pi_int.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define INLINE_PARAMS 8

typedef struct {
  char *name;
  size_t bitwidth;
  char byte0_mask;
} _action_param_data_t;

typedef struct _action_data_s {
  char *name;
  pi_p4_id_t action_id;
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

static size_t get_action_idx(pi_p4_id_t action_id) {
  assert(PI_GET_TYPE_ID(action_id) == PI_ACTION_ID);
  return action_id & 0xFFFF;
}

static size_t get_param_idx(pi_p4_id_t param_id) {
  assert(PI_GET_TYPE_ID(param_id) == PI_ACTION_PARAM_ID);
  return param_id & 0xFF;
}

static size_t get_action_idx_from_param_id(pi_p4_id_t param_id) {
  return ((param_id & 0xffff00) >> 8);
}

static _action_data_t *get_action(const pi_p4info_t *p4info,
                                  pi_p4_id_t action_id) {
  size_t action_idx = get_action_idx(action_id);
  assert(action_idx < p4info->num_actions);
  return &p4info->actions[action_idx];
}

static pi_p4_id_t *get_param_ids(_action_data_t *action) {
  return (action->num_params <= INLINE_PARAMS) ?
      action->param_ids.direct : action->param_ids.indirect;
}

static _action_param_data_t *get_param_data(_action_data_t *action) {
  return (action->num_params <= INLINE_PARAMS) ?
      action->param_data.direct : action->param_data.indirect;
}

static _action_param_data_t *get_param_data_at(_action_data_t *action,
                                               pi_p4_id_t param_id) {
  size_t param_idx = get_param_idx(param_id);
  assert(param_idx < action->num_params);
  return (action->num_params <= INLINE_PARAMS) ?
      &action->param_data.direct[param_idx] :
      &action->param_data.indirect[param_idx];
}

static pi_p4_id_t get_param_id(_action_data_t *action, const char *name) {
  pi_p4_id_t *param_ids = get_param_ids(action);
  _action_param_data_t *param_data = get_param_data(action);
  for (size_t i = 0; i < action->num_params; i++) {
    if (!strcmp(name, param_data[i].name))
      return param_ids[i];
  }
  return 0;
}

void pi_p4info_action_init(pi_p4info_t *p4info, size_t num_actions) {
  p4info->num_actions = num_actions;
  p4info->actions = calloc(num_actions, sizeof(_action_data_t));
  p4info->action_name_map = (Pvoid_t) NULL;
}

void pi_p4info_action_free(pi_p4info_t *p4info) {
  for (size_t i = 0; i < p4info->num_actions; i++) {
    _action_data_t *action = &p4info->actions[i];
    if (!action->name) continue;
    free(action->name);
    _action_param_data_t *params = get_param_data(action);
    for (size_t j = 0; j < action->num_params; j++) {
      _action_param_data_t *param = &params[j];
      if (!param->name) continue;
      free(param->name);
    }
    if (action->num_params > INLINE_PARAMS) {
      assert(action->param_ids.indirect);
      assert(action->param_data.indirect);
      free(action->param_ids.indirect);
      free(action->param_data.indirect);
    }
  }
  free(p4info->actions);
  Word_t Rc_word;
  JSLFA(Rc_word, p4info->action_name_map);
}

void pi_p4info_action_add(pi_p4info_t *p4info, pi_p4_id_t action_id,
                          const char *name, size_t num_params) {
  _action_data_t *action = get_action(p4info, action_id);
  action->name = strdup(name);
  action->action_id = action_id;
  action->num_params = num_params;
  if (num_params > INLINE_PARAMS) {
    action->param_ids.indirect = calloc(num_params, sizeof(pi_p4_id_t));
    action->param_data.indirect =
        calloc(num_params, sizeof(_action_param_data_t));
  }

  Word_t *action_id_ptr;
  JSLI(action_id_ptr, p4info->action_name_map, (const uint8_t *) action->name);
  *action_id_ptr = action_id;
}

static char get_byte0_mask(size_t bitwidth) {
  if (bitwidth % 8 == 0) return 0xff;
  int nbits = bitwidth % 8;
  return ((1 << nbits) - 1);
}

static bool param_matches_action(pi_p4_id_t action_id, pi_p4_id_t param_id) {
  return get_action_idx(action_id) == get_action_idx_from_param_id(param_id);
}

void pi_p4info_action_add_param(pi_p4info_t *p4info, pi_p4_id_t action_id,
                                pi_p4_id_t param_id, const char *name,
                                size_t bitwidth) {
  assert(param_matches_action(action_id, param_id));
  _action_data_t *action = get_action(p4info, action_id);
  _action_param_data_t *param_data = get_param_data_at(action, param_id);
  param_data->name = strdup(name);
  param_data->bitwidth = bitwidth;
  param_data->byte0_mask = get_byte0_mask(bitwidth);
  size_t param_idx = get_param_idx(param_id);
  pi_p4_id_t *param_ids = get_param_ids(action);
  param_ids[param_idx] = param_id;
}

size_t pi_p4info_action_get_num(const pi_p4info_t *p4info) {
  return p4info->num_actions;
}

pi_p4_id_t pi_p4info_action_id_from_name(const pi_p4info_t *p4info,
                                         const char *name) {
  Word_t *action_id_ptr;
  JSLG(action_id_ptr, p4info->action_name_map, (const uint8_t *) name);
  assert (action_id_ptr);
  return *action_id_ptr;
}

const char *pi_p4info_action_name_from_id(const pi_p4info_t *p4info,
                                          pi_p4_id_t action_id) {
  _action_data_t *action = get_action(p4info, action_id);
  return action->name;
}

size_t pi_p4info_action_num_params(const pi_p4info_t *p4info,
                                   pi_p4_id_t action_id) {
  _action_data_t *action = get_action(p4info, action_id);
  return action->num_params;
}

const pi_p4_id_t *pi_p4info_action_get_params(const pi_p4info_t *p4info,
                                              pi_p4_id_t action_id,
                                              size_t *num_params) {
  _action_data_t *action = get_action(p4info, action_id);
  *num_params = action->num_params;
  return get_param_ids(action);
}

pi_p4_id_t pi_p4info_action_param_id_from_name(const pi_p4info_t *p4info,
                                               pi_p4_id_t action_id,
                                               const char *name) {
  _action_data_t *action = get_action(p4info, action_id);
  return get_param_id(action, name);
}

const char *pi_p4info_action_param_name_from_id(const pi_p4info_t *p4info,
                                                pi_p4_id_t param_id) {
  _action_data_t *action =
      &p4info->actions[get_action_idx_from_param_id(param_id)];
  return get_param_data_at(action, param_id)->name;
}

size_t pi_p4info_action_param_bitwidth(const pi_p4info_t *p4info,
                                       pi_p4_id_t param_id) {
  _action_data_t *action =
      &p4info->actions[get_action_idx_from_param_id(param_id)];
  return get_param_data_at(action, param_id)->bitwidth;
}

char pi_p4info_action_param_byte0_mask(const pi_p4info_t *p4info,
                                       pi_p4_id_t param_id) {
  _action_data_t *action =
      &p4info->actions[get_action_idx_from_param_id(param_id)];
  return get_param_data_at(action, param_id)->byte0_mask;
}

#define PI_P4INFO_A_ITERATOR_FIRST (PI_ACTION_ID << 24)
#define PI_P4INFO_A_ITERATOR_END ((PI_ACTION_ID << 24) | 0xffffff)

pi_p4_id_t pi_p4info_action_begin(const pi_p4info_t *p4info) {
  return (p4info->num_actions == 0) ? PI_P4INFO_A_ITERATOR_END
      : PI_P4INFO_A_ITERATOR_FIRST;
}

pi_p4_id_t pi_p4info_action_next(const pi_p4info_t *p4info, pi_p4_id_t id) {
  return ((id & 0xffffff) == p4info->num_actions - 1) ? PI_P4INFO_A_ITERATOR_END
      : (id + 1);
}

pi_p4_id_t pi_p4info_action_end(const pi_p4info_t *p4info) {
  (void) p4info;
  return PI_P4INFO_A_ITERATOR_END;
}
