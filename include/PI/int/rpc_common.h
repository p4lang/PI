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

#ifndef PI_INT_RPC_COMMON_H_
#define PI_INT_RPC_COMMON_H_

typedef enum {
  PI_RPC_INIT = 0,
  PI_RPC_ASSIGN_DEVICE,
  PI_RPC_REMOVE_DEVICE,
  PI_RPC_DESTROY,

  PI_RPC_SESSION_INIT,
  PI_RPC_SESSION_CLEANUP,

  PI_RPC_TABLE_ENTRY_ADD,
  PI_RPC_TABLE_DEFAULT_ACTION_SET,
  PI_RPC_TABLE_DEFAULT_ACTION_GET,
  /* PI_RPC_TABLE_DEFAULT_ACTION_DONE, */
  PI_RPC_TABLE_ENTRY_DELETE,
  PI_RPC_TABLE_ENTRY_MODIFY,
  PI_RPC_TABLE_ENTRIES_FETCH,
  /* PI_RPC_TABLE_ENTRIES_FETCH_DONE, */

  // act profs
  // TODO(antonin): move
  PI_RPC_ACT_PROF_MBR_CREATE,

  // rpc management
  // retrieve state for sync-up when rpc client is started
  PI_RPC_INT_GET_STATE = 256,
} pi_rpc_type_t;

typedef uint32_t pi_rpc_id_t;
typedef pi_rpc_id_t s_pi_rpc_id_t;

size_t emit_rpc_id(char *dst, pi_rpc_id_t v);
size_t retrieve_rpc_id(const char *src, pi_rpc_id_t *v);

typedef uint32_t s_pi_rpc_type_t;

size_t emit_rpc_type(char *dst, pi_rpc_type_t v);
size_t retrieve_rpc_type(const char *src, pi_rpc_type_t *v);

typedef struct __attribute__((packed)) {
  s_pi_rpc_id_t id;
  s_pi_status_t type;
} rep_hdr_t;

typedef struct __attribute__((packed)) {
  s_pi_rpc_id_t id;
  s_pi_rpc_type_t type;
} req_hdr_t;

struct pi_table_entry_t;

size_t table_entry_size(const pi_table_entry_t *table_entry);
size_t emit_table_entry(char *dst, const pi_table_entry_t *table_entry);
size_t retrieve_table_entry(char *src, pi_table_entry_t *table_entry, int copy);

size_t action_data_size(const pi_action_data_t *action_data);
size_t emit_action_data(char *dst, const pi_action_data_t *action_data);
size_t retrieve_action_data(char *src, pi_action_data_t **action_data,
                            int copy);

#endif  // PI_INT_RPC_COMMON_H_
