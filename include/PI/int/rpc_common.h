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

#ifndef PI_INT_RPC_COMMON_H_
#define PI_INT_RPC_COMMON_H_

#define _DEV_TGT_SIZE (2 * sizeof(uint32_t))

typedef enum {
  PI_RPC_INIT,
  PI_RPC_ASSIGN_DEVICE,
  PI_RPC_REMOVE_DEVICE,
  PI_RPC_DESTROY,

  PI_RPC_TABLE_ENTRY_ADD,
  PI_RPC_TABLE_DEFAULT_ACTION_SET,
  PI_RPC_TABLE_DEFAULT_ACTION_GET,
  /* PI_RPC_TABLE_DEFAULT_ACTION_DONE, */
  PI_RPC_TABLE_ENTRY_DELETE,
  PI_RPC_TABLE_ENTRY_MODIFY,
  PI_RPC_TABLE_ENTRIES_FETCH,
  /* PI_RPC_TABLE_ENTRIES_FETCH_DONE, */
} pi_rpc_msg_id_t;

struct pi_table_entry_t;

size_t table_entry_size(const pi_table_entry_t *table_entry);
size_t emit_table_entry(char *dst, const pi_table_entry_t *table_entry);
size_t retrieve_table_entry(char *src, pi_table_entry_t *table_entry, int copy);

#endif  // PI_INT_RPC_COMMON_H_
