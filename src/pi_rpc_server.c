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

#include "PI/target/pi_imp.h"
#include "PI/target/pi_tables_imp.h"
#include "PI/int/pi_int.h"
#include "PI/int/serialize.h"
#include "PI/int/rpc_common.h"

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  int init;
  pi_rpc_id_t req_id;
  int s;
} pi_rpc_state_t;

/* static const char *addr = "ipc:///tmp/pi_rpc.ipc"; */
static char *addr = NULL;

static pi_rpc_state_t state;

static size_t emit_rep_hdr(char *hdr, pi_status_t status) {
  size_t s = 0;
  s += emit_rpc_id(hdr, state.req_id);
  s += emit_status(hdr + s, status);
  return s;
}

static void send_status(pi_status_t status) {
  rep_hdr_t rep;
  size_t s = emit_rep_hdr((char *) &rep, status);
  int bytes = nn_send(state.s, &rep, sizeof(rep), 0);
  assert((size_t) bytes == s);
}

static size_t get_device_version(pi_dev_id_t dev_id) {
  return pi_get_device_info(dev_id)->version;
}

static void __pi_init(char *req) {
  printf("RPC: _pi_init\n");

  (void) req;
  size_t num_devices;
  pi_device_info_t *devices = pi_get_devices(&num_devices);
  pi_status_t status = PI_STATUS_SUCCESS;
  if (!devices) {  // not init yet
    assert(num_devices == 0);
    status = _pi_init(NULL);
  }

  typedef struct {
    char *json;
    size_t size;
  } p4info_tmp_t;
  p4info_tmp_t *p4info_tmp = NULL;

  size_t s = sizeof(rep_hdr_t);
  s += sizeof(uint32_t);  // num assigned devices

  if (num_devices > 0) {
    p4info_tmp = calloc(num_devices, sizeof(*p4info_tmp));
  }

  size_t num_assigned_devices = 0;

  for (pi_dev_id_t dev_id = 0; dev_id < num_devices; dev_id++) {
    if (devices[dev_id].version == 0) continue;
    num_assigned_devices++;
    s += sizeof(s_pi_dev_id_t);
    s += sizeof(uint32_t);  // version
    p4info_tmp[dev_id].json = pi_serialize_config(devices[dev_id].p4info, 0);
    p4info_tmp[dev_id].size = strlen(p4info_tmp[dev_id].json) + 1;
    s += p4info_tmp[dev_id].size;
  }

  char *rep = nn_allocmsg(s, 0);
  char *rep_ = rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_uint32(rep_, num_assigned_devices);
  for (pi_dev_id_t dev_id = 0; dev_id < num_devices; dev_id++) {
    if (devices[dev_id].version == 0) continue;
    rep_ += emit_dev_id(rep_, dev_id);
    rep_ += emit_uint32(rep_, devices[dev_id].version);
    memcpy(rep_, p4info_tmp[dev_id].json, p4info_tmp[dev_id].size);
    rep_ += p4info_tmp[dev_id].size;
  }

  if (num_devices > 0) {
    assert(p4info_tmp);
    free(p4info_tmp);
  }

  assert((size_t) (rep_ - rep) == s);

  int bytes = nn_send(state.s, &rep, NN_MSG, 0);
  assert((size_t) bytes == s);
}

static void __pi_assign_device(char *req) {
  printf("RPC: _pi_assign_device\n");

  pi_status_t status;
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);

  if (get_device_version(dev_id) > 0) {
    send_status(PI_STATUS_DEV_ALREADY_ASSIGNED);
    return;
  }

  size_t p4info_size = strlen(req) + 1;
  pi_p4info_t *p4info;
  // TODO(antonin): when is this destroyed?
  status = pi_add_config(req, PI_CONFIG_TYPE_NATIVE_JSON, &p4info);
  if (status != PI_STATUS_SUCCESS) {
    send_status(status);
    return;
  }
  req += p4info_size;

  // extras
  uint32_t num_extras;
  req += retrieve_uint32(req, &num_extras);

  size_t extras_size = sizeof(pi_assign_extra_t) * (num_extras + 1);
  pi_assign_extra_t *extras = malloc(extras_size);
  memset(extras, 0, extras_size);
  for (size_t i = 0; i < num_extras; i++) {
    extras[i].key = req;
    req = strchr(req, '\0') + 1;
    extras[i].v = req;
    req = strchr(req, '\0') + 1;
  }
  extras[num_extras].end_of_extras = 1;

  status = _pi_assign_device(dev_id, p4info, extras);
  free(extras);

  if (status == PI_STATUS_SUCCESS) pi_update_device_config(dev_id, p4info);

  send_status(status);
}

static void __pi_remove_device(char *req) {
  printf("RPC: _pi_remove_device\n");

  pi_dev_id_t dev_id;
  retrieve_dev_id(req, &dev_id);

  if (get_device_version(dev_id) == 0) {
    send_status(PI_STATUS_DEV_NOT_ASSIGNED);
    return;
  }

  pi_status_t status = _pi_remove_device(dev_id);

  if (status == PI_STATUS_SUCCESS) pi_reset_device_config(dev_id);

  send_status(status);;
}

static void __pi_destroy(char *req) {
  printf("RPC: _pi_destroy\n");

  (void) req;
  send_status(_pi_destroy());
}

static void __pi_session_init(char *req) {
  printf("RPC: _pi_session_init\n");

  (void) req;

  pi_session_handle_t sess = 0;
  pi_status_t status = _pi_session_init(&sess);

  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_session_handle_t h;
  } rep_t;
  rep_t rep;
  char *rep_ = (char *) &rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_session_handle(rep_, sess);

  int bytes = nn_send(state.s, &rep, sizeof(rep), 0);
  assert(bytes == sizeof(rep));
}

static void __pi_session_cleanup(char *req) {
  printf("RPC: _pi_session_cleanup\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);

  send_status(_pi_session_cleanup(sess));
}

static void __pi_table_entry_add(char *req) {
  printf("RPC: _pi_table_entry_add\n");

  // TODO(antonin): find a way to take care of p4info for mk and ad
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  uint32_t mk_size;
  req += retrieve_uint32(req, &mk_size);
  pi_match_key_t match_key;
  match_key.p4info = NULL;  // TODO(antonin)
  match_key.table_id = table_id;
  match_key.data_size = mk_size;
  match_key.data = req;
  req += mk_size;

  pi_table_entry_t table_entry;
  pi_action_data_t action_data;
  action_data.p4info = NULL;  // TODO(antonin)
  // TODO(antonin): indirect
  table_entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  table_entry.entry.action_data = &action_data;
  req += retrieve_table_entry(req, &table_entry, 0);

  uint32_t overwrite;
  req += retrieve_uint32(req, &overwrite);

  pi_entry_handle_t entry_handle;
  pi_status_t status = _pi_table_entry_add(sess, dev_tgt, table_id, &match_key,
                                           &table_entry, overwrite,
                                           &entry_handle);

  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_entry_handle_t h;
  } rep_t;
  rep_t rep;
  char *rep_ = (char *) &rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_entry_handle(rep_, entry_handle);

  int bytes = nn_send(state.s, &rep, sizeof(rep), 0);
  assert(bytes == sizeof(rep));
}

static void __pi_table_default_action_set(char *req) {
  printf("RPC: _pi_table_default_action_set\n");

  // TODO(antonin): find a way to take care of p4info for ad
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_tgt_t dev_tgt;
  req += retrieve_dev_tgt(req, &dev_tgt);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  pi_table_entry_t table_entry;
  pi_action_data_t action_data;
  action_data.p4info = NULL;  // TODO(antonin)
  // TODO(antonin): indirect
  table_entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  table_entry.entry.action_data = &action_data;
  req += retrieve_table_entry(req, &table_entry, 0);

  pi_status_t status = _pi_table_default_action_set(sess, dev_tgt, table_id,
                                                    &table_entry);
  send_status(status);
}

static void __pi_table_default_action_get(char *req) {
  printf("RPC: _pi_table_default_action_get\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  pi_table_entry_t default_entry;
  pi_status_t status = _pi_table_default_action_get(sess, dev_id, table_id,
                                                    &default_entry);

  size_t s = 0;
  s += sizeof(rep_hdr_t);
  s += table_entry_size(&default_entry);

  char *rep = nn_allocmsg(s, 0);
  char *rep_ = rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_table_entry(rep_, &default_entry);

  // release target memory
  _pi_table_default_action_done(sess, &default_entry);

  // make sure I have copied exactly the right amount
  assert((size_t) (rep_ - rep) == s);

  int bytes = nn_send(state.s, &rep, NN_MSG, 0);
  assert((size_t) bytes == s);
}

static void __pi_table_entry_delete(char *req) {
  printf("RPC: _pi_table_entry_delete\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);
  pi_entry_handle_t h;
  req += retrieve_entry_handle(req, &h);

  send_status(_pi_table_entry_delete(sess, dev_id, table_id, h));
}

static void __pi_table_entry_modify(char *req) {
  printf("RPC: _pi_table_entry_modify\n");

  // TODO(antonin): find a way to take care of p4info for mk and ad
  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);
  pi_entry_handle_t h;
  req += retrieve_entry_handle(req, &h);

  pi_table_entry_t table_entry;
  pi_action_data_t action_data;
  action_data.p4info = NULL;  // TODO(antonin)
  // TODO(antonin): indirect
  table_entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  table_entry.entry.action_data = &action_data;
  req += retrieve_table_entry(req, &table_entry, 0);

  send_status(_pi_table_entry_modify(sess, dev_id, table_id, h, &table_entry));
}

static void __pi_table_entries_fetch(char *req) {
  printf("RPC: _pi_table_entries_fetch\n");

  pi_session_handle_t sess;
  req += retrieve_session_handle(req, &sess);
  pi_dev_id_t dev_id;
  req += retrieve_dev_id(req, &dev_id);
  pi_p4_id_t table_id;
  req += retrieve_p4_id(req, &table_id);

  pi_table_fetch_res_t res;
  pi_status_t status = _pi_table_entries_fetch(sess, dev_id, table_id, &res);

  if (status != PI_STATUS_SUCCESS) {
    send_status(status);
    return;
  }

  size_t s = 0;
  s += sizeof(rep_hdr_t);
  s += sizeof(uint32_t);  // num entries
  s += sizeof(uint32_t);  // mkey nbytes
  s += sizeof(uint32_t);  // entries_size (in bytes)
  s += res.entries_size;

  char *rep = nn_allocmsg(s, 0);
  char *rep_ = rep;
  rep_ += emit_rep_hdr(rep_, status);
  rep_ += emit_uint32(rep_, res.num_entries);
  rep_ += emit_uint32(rep_, res.mkey_nbytes);
  rep_ += emit_uint32(rep_, res.entries_size);
  memcpy(rep_, res.entries, res.entries_size);
  rep_ += res.entries_size;

  // release target memory
  _pi_table_entries_fetch_done(sess, &res);

  // make sure I have copied exactly the right amount
  assert((size_t) (rep_ - rep) == s);

  int bytes = nn_send(state.s, &rep, NN_MSG, 0);
  assert((size_t) bytes == s);
}

pi_status_t pi_rpc_server_run(char *rpc_addr) {
  assert(!state.init);
  if (rpc_addr)
    addr = strdup((char *) rpc_addr);
  else
    addr = "ipc:///tmp/pi_rpc.ipc";
  state.s = nn_socket(AF_SP, NN_REP);
  if (state.s < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  if (nn_bind(state.s, addr) < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  state.init = 1;

  while (1) {
    char *req = NULL;
    int bytes = nn_recv(state.s, &req, NN_MSG, 0);
    if (bytes < 0) return PI_STATUS_RPC_TRANSPORT_ERROR;
    if (bytes == 0) continue;

    pi_rpc_type_t type;
    char *req_ = req;
    req_ += retrieve_rpc_id(req_, &state.req_id);
    printf("req_id: %u\n", state.req_id);
    req_ += retrieve_rpc_type(req_, &type);

    switch (type) {
      case PI_RPC_INIT:
        __pi_init(req_); break;
      case PI_RPC_ASSIGN_DEVICE:
        __pi_assign_device(req_); break;
      case PI_RPC_REMOVE_DEVICE:
        __pi_remove_device(req_); break;
      case PI_RPC_DESTROY:
        __pi_destroy(req_); break;
      case PI_RPC_SESSION_INIT:
        __pi_session_init(req_); break;
      case PI_RPC_SESSION_CLEANUP:
        __pi_session_cleanup(req_); break;
      case PI_RPC_TABLE_ENTRY_ADD:
        __pi_table_entry_add(req_); break;
      case PI_RPC_TABLE_DEFAULT_ACTION_SET:
        __pi_table_default_action_set(req_); break;
      case PI_RPC_TABLE_DEFAULT_ACTION_GET:
        __pi_table_default_action_get(req_); break;
      case PI_RPC_TABLE_ENTRY_DELETE:
        __pi_table_entry_delete(req_); break;
      case PI_RPC_TABLE_ENTRY_MODIFY:
        __pi_table_entry_modify(req_); break;
      case PI_RPC_TABLE_ENTRIES_FETCH:
        __pi_table_entries_fetch(req_); break;
      default:
        assert(0);
    }

    nn_freemsg(req);
  }

  return PI_STATUS_SUCCESS;
}

// some helper functions declared in rpc_common.h

size_t emit_rpc_id(char *dst, pi_rpc_id_t v) {
  return emit_uint32(dst, v);
}

size_t retrieve_rpc_id(const char *src, pi_rpc_id_t *v) {
  return retrieve_uint32(src, v);
}

size_t emit_rpc_type(char *dst, pi_rpc_type_t v) {
  return emit_uint32(dst, v);
}

size_t retrieve_rpc_type(const char *src, pi_rpc_type_t *v) {
  return retrieve_uint32(src, v);
}

size_t table_entry_size(const pi_table_entry_t *table_entry) {
  size_t s = 0;
  s += sizeof(s_pi_p4_id_t);  // action_id
  s += sizeof(uint32_t);  // action data size
  // for the specific case of no default action (fetch)
  if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_DATA)
    s += table_entry->entry.action_data->data_size;
  // TODO(antonin): properties
  return s;
}

size_t emit_table_entry(char *dst, const pi_table_entry_t *table_entry) {
  size_t s = 0;
  pi_p4_id_t action_id = PI_INVALID_ID;
  size_t ad_size = 0;
  // TODO(antonin): indirect
  if (table_entry->entry_type == PI_ACTION_ENTRY_TYPE_DATA) {
    action_id = table_entry->entry.action_data->action_id;
    ad_size = table_entry->entry.action_data->data_size;
  }
  s += emit_p4_id(dst, action_id);
  s += emit_uint32(dst + s, ad_size);
  if (ad_size > 0) {
    memcpy(dst + s, table_entry->entry.action_data->data, ad_size);
    s += ad_size;
  }
  // TODO(antonin): properties
  return s;
}

size_t retrieve_table_entry(char *src, pi_table_entry_t *table_entry,
                            int copy) {
  size_t s = 0;
  pi_p4_id_t action_id;
  s += retrieve_p4_id(src, &action_id);
  uint32_t ad_size;
  s += retrieve_uint32(src + s, &ad_size);

  // TODO(antonin): indirect
  if (action_id == PI_INVALID_ID) {
    table_entry->entry_type = PI_ACTION_ENTRY_TYPE_NONE;
  } else {
    table_entry->entry_type = PI_ACTION_ENTRY_TYPE_DATA;

    pi_action_data_t *action_data;
    if (copy) {
      // no alignment issue with malloc
      char *ad = malloc(sizeof(pi_action_data_t) + ad_size);
      action_data = (pi_action_data_t *) ad;
      action_data->data = ad + sizeof(pi_action_data_t);
      table_entry->entry.action_data = action_data;
    } else {
      action_data = table_entry->entry.action_data;
    }

    action_data->action_id = action_id;
    action_data->data_size = ad_size;

    if (copy) {
      memcpy(action_data->data, src + s, ad_size);
    } else {
      action_data->data = src + s;
    }
  }

  s += ad_size;

  // TODO(antonin): properties
  return s;
}
