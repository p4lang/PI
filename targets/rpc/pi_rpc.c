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
  RPC built on an abstract transport mechanism (let's start with nanomsg reqrep)
  Request: id | type | dev_tgt / dev_id | body ...
  Reply: id | type | status | body ...

  for p4info, need to write some JSON serialization code
*/

#include <PI/pi.h>
#include <PI/int/pi_int.h>
#include <PI/int/serialize.h>
#include <PI/int/rpc_common.h>

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct {
  int init;
  uint32_t req_id;
  int s;
} pi_rpc_state_t;

static const char *addr = "ipc:///tmp/pi_rpc.ipc";

static pi_rpc_state_t state;

static pi_status_t wait_for_status(uint32_t req_id) {
  typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t status;
  } msg_t;
  msg_t msg;
  int rc = nn_recv(state.s, &msg, sizeof(msg), 0);
  if (rc != sizeof(msg)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  uint32_t status;
  if (req_id != msg.id) return PI_STATUS_RPC_TRANSPORT_ERROR;
  retrieve_uint32((char *) &msg + sizeof(msg.id), &status);
  printf("status: %d\n", status);
  return status;
}

pi_status_t _pi_init() {
  assert(!state.init);
  state.s = nn_socket(AF_SP, NN_REQ);
  if (state.s < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  if (nn_connect(state.s, addr) < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  state.init = 1;

  // id and type
  char msg[sizeof(uint32_t) + sizeof(uint32_t)];
  char *msg_ = msg;
  uint32_t req_id = state.req_id++;
  msg_ += emit_uint32(msg_, req_id);
  emit_uint32(msg_, PI_RPC_INIT);

  int rc = nn_send(state.s, msg, sizeof(msg), 0);
  if (rc != sizeof(msg)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_assign_device(uint16_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t type;
    uint32_t dev_id;
  } msg_t;
  char *p4info_json = pi_serialize_config(p4info);
  size_t p4info_size = strlen(p4info_json) + 1;
  size_t num_extras = 0;
  size_t extra_size = sizeof(uint32_t);  // for num extras
  pi_assign_extra_t *extra_ = extra;
  for (; !extra_->end_of_extras; extra_++) {
    num_extras++;
    extra_size += strlen(extra_->key) + 1 + strlen(extra_->v) + 1;
  }
  size_t s = sizeof(msg_t) + p4info_size + extra_size;
  char *msg = nn_allocmsg(s, 0);
  char *msg_ = msg;
  uint32_t req_id = state.req_id++;
  msg_ += emit_uint32(msg_, req_id);
  msg_ += emit_uint32(msg_, PI_RPC_ASSIGN_DEVICE);
  msg_ += emit_uint32(msg_, dev_id);
  memcpy(msg_, p4info_json, p4info_size);
  msg_ += p4info_size;
  free(p4info_json);
  msg_ += emit_uint32(msg_, num_extras);
  extra_ = extra;
  for (; !extra_->end_of_extras; extra_++) {
    strcpy(msg_, extra_->key);
    msg_ = strchr(msg_, '\0') + 1;
    strcpy(msg_, extra_->v);
    msg_ = strchr(msg_, '\0') + 1;
  }

  int rc = nn_send(state.s, &msg, NN_MSG, 0);
  if ((size_t) rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_remove_device(uint16_t dev_id) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t type;
    uint32_t dev_id;
  } msg_t;
  msg_t msg;
  char *msg_ = (char *) &msg;
  uint32_t req_id = state.req_id++;
  msg_ += emit_uint32(msg_, req_id);
  msg_ += emit_uint32(msg_, PI_RPC_REMOVE_DEVICE);
  emit_uint32(msg_, dev_id);

  int rc = nn_send(state.s, &msg, sizeof(msg), 0);
  if (rc != sizeof(msg)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_destroy() {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  // id and type
  char msg[sizeof(uint32_t) + sizeof(uint32_t)];
  char *msg_ = msg;
  uint32_t req_id = state.req_id++;
  msg_ += emit_uint32(msg_, req_id);
  emit_uint32(msg_, PI_RPC_DESTROY);

  int rc = nn_send(state.s, msg, sizeof(msg), 0);
  if (rc != sizeof(msg)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}


// Tables

static size_t emit_dev_tgt(char *dst, pi_dev_tgt_t dev_tgt) {
  size_t s = 0;
  s += emit_uint32(dst, dev_tgt.dev_id);
  s += emit_uint32(dst + s, dev_tgt.dev_pipe_mask);
  return s;
}

// TODO(antonin): unify with wait_for_status?
static pi_status_t wait_for_handle(uint32_t req_id,
                                   pi_entry_handle_t *entry_handle) {
  assert(sizeof(pi_entry_handle_t) == sizeof(uint64_t));
  typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t status;
    uint64_t h;
  } msg_t;
  msg_t msg;
  const char *msg_ = (char *) &msg;
  int rc = nn_recv(state.s, &msg, sizeof(msg), 0);
  if (rc != sizeof(msg)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  uint32_t status;
  if (req_id != msg.id) return PI_STATUS_RPC_TRANSPORT_ERROR;
  msg_ += sizeof(msg.id);
  msg_ += retrieve_uint32(msg_, &status);
  printf("status: %d\n", status);
  retrieve_uint64(msg_, entry_handle);
  return status;
}

pi_status_t _pi_table_entry_add(const pi_dev_tgt_t dev_tgt,
                                const pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                const int overwrite,
                                pi_entry_handle_t *entry_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += 2 * sizeof(uint32_t);  // id and type
  s += _DEV_TGT_SIZE;
  s += sizeof(uint32_t);  // table_id
  s += sizeof(uint32_t) + match_key->data_size;  // match key with size
  s += table_entry_size(table_entry);
  s += sizeof(uint32_t);  // overwrite

  char *msg = nn_allocmsg(s, 0);
  char *msg_ = msg;
  uint32_t req_id = state.req_id++;
  msg_ += emit_uint32(msg_, req_id);
  msg_ += emit_uint32(msg_, PI_RPC_TABLE_ENTRY_ADD);
  msg_ += emit_dev_tgt(msg_, dev_tgt);
  msg_ += emit_uint32(msg_, table_id);
  msg_ += emit_uint32(msg_, match_key->data_size);
  memcpy(msg_, match_key->data, match_key->data_size);
  msg_ += match_key->data_size;
  msg_ += emit_table_entry(msg_, table_entry);
  msg_ += emit_uint32(msg_, overwrite);

  // make sure I have copied exactly the right amount
  assert((size_t) (msg_ - msg) == s);

  int rc = nn_send(state.s, &msg, NN_MSG, 0);
  if ((size_t) rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_handle(req_id, entry_handle);
}

pi_status_t _pi_table_default_action_set(const pi_dev_tgt_t dev_tgt,
                                         const pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += 2 * sizeof(uint32_t);  // id and type
  s += _DEV_TGT_SIZE;
  s += sizeof(uint32_t);  // table_id
  s += table_entry_size(table_entry);

  char *msg = nn_allocmsg(s, 0);
  char *msg_ = msg;
  uint32_t req_id = state.req_id++;
  msg_ += emit_uint32(msg_, req_id);
  msg_ += emit_uint32(msg_, PI_RPC_TABLE_DEFAULT_ACTION_SET);
  msg_ += emit_dev_tgt(msg_, dev_tgt);
  msg_ += emit_uint32(msg_, table_id);
  msg_ += emit_table_entry(msg_, table_entry);

  // make sure I have copied exactly the right amount
  assert((size_t) (msg_ - msg) == s);

  int rc = nn_send(state.s, &msg, NN_MSG, 0);
  if ((size_t) rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_table_default_action_get(const pi_dev_id_t dev_id,
                                         const pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t type;
    uint32_t dev_id;
    uint32_t table_id;
  } msg_t;
  msg_t msg;
  uint32_t req_id = state.req_id++;
  emit_uint32((char *) &msg.id, req_id);
  emit_uint32((char *) &msg.type, PI_RPC_TABLE_DEFAULT_ACTION_GET);
  emit_uint32((char *) &msg.dev_id, dev_id);
  emit_uint32((char *) &msg.table_id, table_id);

  int rc = nn_send(state.s, &msg, sizeof(msg), 0);
  if (rc != sizeof(msg)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  char *rep = NULL;
  int bytes = nn_recv(state.s, &rep, NN_MSG, 0);
  if (bytes <= 0) return PI_STATUS_RPC_TRANSPORT_ERROR;

  char *rep_ = rep;
  uint32_t id, status;
  rep_ += retrieve_uint32(rep_, &id);
  rep_ += retrieve_uint32(rep_, &status);
  if (req_id != id) return PI_STATUS_RPC_TRANSPORT_ERROR;
  if (status != PI_STATUS_SUCCESS) {
    nn_freemsg(rep);
    return status;
  }

  // 1 means make a copy of the action data
  rep_ += retrieve_table_entry(rep_, table_entry, 1);
  table_entry->action_data->p4info = NULL;  // TODO(antonin)

  nn_freemsg(rep);
  return status;
}

pi_status_t _pi_table_default_action_done(pi_table_entry_t *table_entry) {
  // release memory allocated in retrieve_table_entry
  free(table_entry->action_data);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_delete(const pi_dev_id_t dev_id,
                                   const pi_p4_id_t table_id,
                                   const pi_entry_handle_t entry_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t type;
    uint32_t dev_id;
    uint32_t table_id;
    uint64_t h;
  } msg_t;
  msg_t msg;
  uint32_t req_id = state.req_id++;
  emit_uint32((char *) &msg.id, req_id);
  emit_uint32((char *) &msg.type, PI_RPC_TABLE_ENTRY_DELETE);
  emit_uint32((char *) &msg.dev_id, dev_id);
  emit_uint32((char *) &msg.table_id, table_id);
  emit_uint64((char *) &msg.h, entry_handle);

  int rc = nn_send(state.s, &msg, sizeof(msg), 0);
  if (rc != sizeof(msg)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_table_entry_modify(const pi_dev_id_t dev_id,
                                   const pi_p4_id_t table_id,
                                   const pi_entry_handle_t entry_handle,
                                   const pi_table_entry_t *table_entry) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += 2 * sizeof(uint32_t);  // id and type
  s += sizeof(uint32_t);  // dev_id
  s += sizeof(uint32_t);  // table_id
  s += sizeof(uint64_t);  // handle
  s += table_entry_size(table_entry);

  char *msg = nn_allocmsg(s, 0);
  char *msg_ = msg;
  uint32_t req_id = state.req_id++;
  msg_ += emit_uint32(msg_, req_id);
  msg_ += emit_uint32(msg_, PI_RPC_TABLE_ENTRY_MODIFY);
  msg_ += emit_uint32(msg_, dev_id);
  msg_ += emit_uint32(msg_, table_id);
  msg_ += emit_uint64(msg_, entry_handle);
  msg_ += emit_table_entry(msg_, table_entry);

  // make sure I have copied exactly the right amount
  assert((size_t) (msg_ - msg) == s);

  int rc = nn_send(state.s, &msg, NN_MSG, 0);
  if ((size_t) rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_table_entries_fetch(const pi_dev_id_t dev_id,
                                    const pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res) {
  (void) dev_id; (void) table_id; (void) res;
  printf("_pi_table_fetch\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entries_fetch_done(pi_table_fetch_res_t *res) {
  (void) res;
  printf("_pi_table_fetch_done\n");
  return PI_STATUS_SUCCESS;
}
