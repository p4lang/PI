/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "pi_rpc.h"

#include <string.h>
#include <stdlib.h>

static pi_status_t wait_for_handle(uint32_t req_id,
                                   pi_entry_handle_t *entry_handle) {
  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_entry_handle_t h;
  } rep_t;
  rep_t rep;
  int rc = nn_recv(state.s, &rep, sizeof(rep), 0);
  if (rc != sizeof(rep)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  pi_status_t status = retrieve_rep_hdr((char *)&rep, req_id);
  // condition on success?
  retrieve_entry_handle((char *)&rep.h, entry_handle);
  return status;
}

pi_status_t _pi_table_entry_add(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                int overwrite,
                                pi_entry_handle_t *entry_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_session_handle_t);
  s += sizeof(s_pi_dev_tgt_t);
  s += sizeof(s_pi_p4_id_t);                     // table_id
  s += sizeof(uint32_t) + match_key->data_size;  // match key with size
  s += table_entry_size(table_entry);
  s += sizeof(uint32_t);  // overwrite

  char *req = nn_allocmsg(s, 0);
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_ENTRY_ADD);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, table_id);
  req_ += emit_uint32(req_, match_key->data_size);
  memcpy(req_, match_key->data, match_key->data_size);
  req_ += match_key->data_size;
  req_ += emit_table_entry(req_, table_entry);
  req_ += emit_uint32(req_, overwrite);

  // make sure I have copied exactly the right amount
  assert((size_t)(req_ - req) == s);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t)rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_handle(req_id, entry_handle);
}

pi_status_t _pi_table_default_action_set(pi_session_handle_t session_handle,
                                         pi_dev_tgt_t dev_tgt,
                                         pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_session_handle_t);
  s += sizeof(s_pi_dev_tgt_t);
  s += sizeof(s_pi_p4_id_t);  // table_id
  s += table_entry_size(table_entry);

  char *req = nn_allocmsg(s, 0);
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_DEFAULT_ACTION_SET);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_tgt(req_, dev_tgt);
  req_ += emit_p4_id(req_, table_id);
  req_ += emit_table_entry(req_, table_entry);

  // make sure I have copied exactly the right amount
  assert((size_t)(req_ - req) == s);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t)rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_table_default_action_get(pi_session_handle_t session_handle,
                                         pi_dev_id_t dev_id,
                                         pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t table_id;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_DEFAULT_ACTION_GET);
  req_ += emit_session_handle(req_, session_handle);
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
  // table_entry->entry.action_data->p4info = NULL;  // TODO(antonin)

  nn_freemsg(rep);
  return status;
}

pi_status_t _pi_table_default_action_done(pi_session_handle_t session_handle,
                                          pi_table_entry_t *table_entry) {
  (void)session_handle;
  // release memory allocated in retrieve_table_entry
  if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_DATA)
    free(table_entry->entry.action_data);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                   pi_entry_handle_t entry_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t table_id;
    s_pi_entry_handle_t h;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_ENTRY_DELETE);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, table_id);
  req_ += emit_entry_handle(req_, entry_handle);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_table_entry_modify(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                   pi_entry_handle_t entry_handle,
                                   const pi_table_entry_t *table_entry) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_session_handle_t);
  s += sizeof(s_pi_dev_id_t);        // dev_id
  s += sizeof(s_pi_p4_id_t);         // table_id
  s += sizeof(s_pi_entry_handle_t);  // handle
  s += table_entry_size(table_entry);

  char *req = nn_allocmsg(s, 0);
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_ENTRY_MODIFY);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_p4_id(req_, table_id);
  req_ += emit_entry_handle(req_, entry_handle);
  req_ += emit_table_entry(req_, table_entry);

  // make sure I have copied exactly the right amount
  assert((size_t)(req_ - req) == s);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t)rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_table_entries_fetch(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t sess;
    s_pi_dev_id_t dev_id;
    s_pi_p4_id_t table_id;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_TABLE_ENTRIES_FETCH);
  req_ += emit_session_handle(req_, session_handle);
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

pi_status_t _pi_table_entries_fetch_done(pi_session_handle_t session_handle,
                                         pi_table_fetch_res_t *res) {
  (void)session_handle;
  free(res->entries);
  return PI_STATUS_SUCCESS;
}
