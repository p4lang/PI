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
  pi_rpc_id_t req_id;
  int s;
} pi_rpc_state_t;

static const char *addr = "ipc:///tmp/pi_rpc.ipc";

static pi_rpc_state_t state;

static pi_status_t retrieve_rep_hdr(const char *rep, pi_rpc_id_t req_id) {
  pi_rpc_id_t recv_id;
  pi_status_t recv_status;
  rep += retrieve_rpc_id(rep, &recv_id);
  if (recv_id != req_id) return PI_STATUS_RPC_TRANSPORT_ERROR;
  rep += retrieve_status(rep, &recv_status);

  return recv_status;
}

static pi_status_t wait_for_status(pi_rpc_id_t req_id) {
  rep_hdr_t rep;
  int rc = nn_recv(state.s, &rep, sizeof(rep), 0);
  if (rc != sizeof(rep)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  return retrieve_rep_hdr((char *) &rep, req_id);
}

static size_t emit_req_hdr(char *hdr, pi_rpc_id_t id, pi_rpc_type_t type) {
  size_t s = 0;
  s += emit_rpc_id(hdr, id);
  s += emit_rpc_type(hdr + s, type);
  return s;
}

pi_status_t _pi_init() {
  assert(!state.init);
  state.s = nn_socket(AF_SP, NN_REQ);
  if (state.s < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  if (nn_connect(state.s, addr) < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  state.init = 1;

  req_hdr_t req;
  pi_rpc_id_t req_id = state.req_id++;
  emit_req_hdr((char *) &req, req_id, PI_RPC_INIT);

  int rc = nn_send(state.s, (char *) &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_dev_id_t dev_id;
  } hdr_t;
  char *p4info_json = pi_serialize_config(p4info);
  size_t p4info_size = strlen(p4info_json) + 1;
  size_t num_extras = 0;
  size_t extra_size = sizeof(uint32_t);  // for num extras
  pi_assign_extra_t *extra_ = extra;
  for (; !extra_->end_of_extras; extra_++) {
    num_extras++;
    extra_size += strlen(extra_->key) + 1 + strlen(extra_->v) + 1;
  }
  size_t s = sizeof(hdr_t) + p4info_size + extra_size;
  char *req = nn_allocmsg(s, 0);
  char *req_ = req;

  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_ASSIGN_DEVICE);
  req_ += emit_dev_id(req_, dev_id);
  memcpy(req_, p4info_json, p4info_size);
  req_ += p4info_size;
  free(p4info_json);
  req_ += emit_uint32(req_, num_extras);
  extra_ = extra;
  for (; !extra_->end_of_extras; extra_++) {
    strcpy(req_, extra_->key);
    req_ = strchr(req_, '\0') + 1;
    strcpy(req_, extra_->v);
    req_ = strchr(req_, '\0') + 1;
  }

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t) rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_remove_device(pi_dev_id_t dev_id) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_dev_id_t dev_id;
  } req_t;
  req_t req;
  char *req_ = (char *) &req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_REMOVE_DEVICE);
  req_ += emit_dev_id(req_, dev_id);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_destroy() {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  req_hdr_t req;
  pi_rpc_id_t req_id = state.req_id++;
  emit_req_hdr((char *) &req, req_id, PI_RPC_DESTROY);

  int rc = nn_send(state.s, (char *) &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}


// Tables

static pi_status_t wait_for_handle(uint32_t req_id,
                                   pi_entry_handle_t *entry_handle) {
  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_entry_handle_t h;
  } rep_t;
  rep_t rep;
  int rc = nn_recv(state.s, &rep, sizeof(rep), 0);
  if (rc != sizeof(rep)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  pi_status_t status = retrieve_rep_hdr((char *) &rep, req_id);
  // condition on success?
  retrieve_entry_handle((char *) &rep.h, entry_handle);
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
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_dev_tgt_t);
  s += sizeof(s_pi_p4_id_t);  // table_id
  s += sizeof(uint32_t) + match_key->data_size;  // match key with size
  s += table_entry_size(table_entry);
  s += sizeof(uint32_t);  // overwrite

  char *req = nn_allocmsg(s, 0);
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_ENTRY_ADD);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, table_id);
  req_ += emit_uint32(req_, match_key->data_size);
  memcpy(req_, match_key->data, match_key->data_size);
  req_ += match_key->data_size;
  req_ += emit_table_entry(req_, table_entry);
  req_ += emit_uint32(req_, overwrite);

  // make sure I have copied exactly the right amount
  assert((size_t) (req_ - req) == s);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t) rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_handle(req_id, entry_handle);
}

pi_status_t _pi_table_default_action_set(const pi_dev_tgt_t dev_tgt,
                                         const pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_dev_tgt_t);
  s += sizeof(s_pi_p4_id_t);  // table_id
  s += table_entry_size(table_entry);

  char *req = nn_allocmsg(s, 0);
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_DEFAULT_ACTION_SET);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, table_id);
  req_ += emit_table_entry(req_, table_entry);

  // make sure I have copied exactly the right amount
  assert((size_t) (req_ - req) == s);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t) rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_table_default_action_get(const pi_dev_id_t dev_id,
                                         const pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t table_id;
  } req_t;
  req_t req;
  char *req_ = (char *) &req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_DEFAULT_ACTION_GET);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, table_id);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  char *rep = NULL;
  int bytes = nn_recv(state.s, &rep, NN_MSG, 0);
  if (bytes <= 0) return PI_STATUS_RPC_TRANSPORT_ERROR;

  char *rep_ = rep;
  pi_status_t status = retrieve_rep_hdr(rep_, req_id);
  if (status != PI_STATUS_SUCCESS) {
    nn_freemsg(rep);
    return status;
  }
  rep_ += sizeof(rep_hdr_t);

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
    req_hdr_t hdr;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t table_id;
    s_pi_entry_handle_t h;
  } req_t;
  req_t req;
  char *req_ = (char *) &req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_ENTRY_DELETE);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, table_id);
  req_ += emit_entry_handle(req_, entry_handle);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_table_entry_modify(const pi_dev_id_t dev_id,
                                   const pi_p4_id_t table_id,
                                   const pi_entry_handle_t entry_handle,
                                   const pi_table_entry_t *table_entry) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_dev_id_t);  // dev_id
  s += sizeof(s_pi_p4_id_t);  // table_id
  s += sizeof(s_pi_entry_handle_t);  // handle
  s += table_entry_size(table_entry);

  char *req = nn_allocmsg(s, 0);
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_ENTRY_MODIFY);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, table_id);
  req_ += emit_entry_handle(req_, entry_handle);
  req_ += emit_table_entry(req_, table_entry);

  // make sure I have copied exactly the right amount
  assert((size_t) (req_ - req) == s);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t) rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_table_entries_fetch(const pi_dev_id_t dev_id,
                                    const pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t table_id;
  } req_t;
  req_t req;
  char *req_ = (char *) &req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_ENTRIES_FETCH);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, table_id);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  (void) res;
  char *rep = NULL;
  int bytes = nn_recv(state.s, &rep, NN_MSG, 0);
  if (bytes <= 0) return PI_STATUS_RPC_TRANSPORT_ERROR;

  char *rep_ = rep;
  pi_status_t status = retrieve_rep_hdr(rep_, req_id);
  if (status != PI_STATUS_SUCCESS) {
    nn_freemsg(rep);
    return status;
  }
  rep_ += sizeof(rep_hdr_t);

  uint32_t tmp32;
  rep_ += retrieve_uint32(rep_, &tmp32);
  res->num_entries = tmp32;
  rep_ += retrieve_uint32(rep_, &tmp32);
  res->mkey_nbytes = tmp32;
  rep_ += retrieve_uint32(rep_, &tmp32);
  res->entries_size = tmp32;

  res->entries = malloc(res->entries_size);
  memcpy(res->entries, rep_, res->entries_size);

  nn_freemsg(rep);
  return status;
}

pi_status_t _pi_table_entries_fetch_done(pi_table_fetch_res_t *res) {
  free(res->entries);
  return PI_STATUS_SUCCESS;
}
