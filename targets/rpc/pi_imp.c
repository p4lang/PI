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

/*
  RPC built on an abstract transport mechanism (let's start with nanomsg reqrep)
  Request: id | type | dev_tgt / dev_id | body ...
  Reply: id | status | body ...

  for p4info, need to write some JSON serialization code
*/

#include <PI/pi.h>
#include <PI/target/pi_imp.h>

#include "pi_rpc.h"

#include <stdlib.h>
#include <string.h>

// TODO(antonin): devices that don't exist at server?
static void process_state_sync(const char *rep) {
  pi_device_lock();
  uint32_t num;
  rep += retrieve_uint32(rep, &num);
  for (size_t i = 0; i < num; i++) {
    pi_dev_id_t dev_id;
    uint32_t version;
    /* uint32_t p4info_size; */
    rep += retrieve_dev_id(rep, &dev_id);
    rep += retrieve_uint32(rep, &version);
    /* rep += retrieve_uint32(rep, &p4info_size); */

    pi_device_info_t *info = pi_get_device_info(dev_id);
    if (info == NULL) {
      pi_create_device_config(dev_id);
      info = pi_get_device_info(dev_id);
    }
    assert(info != NULL);
    assert(info->version < version);
    info->version = version;
    pi_p4info_t *p4info;
    pi_add_config(rep, PI_CONFIG_TYPE_NATIVE_JSON, &p4info);
    info->p4info = p4info;
  }
  pi_device_unlock();
}

static void init_addrs(const pi_remote_addr_t *remote_addr) {
  if (!remote_addr || !remote_addr->rpc_addr)
    rpc_addr = strdup("ipc:///tmp/pi_rpc.ipc");
  else
    rpc_addr = strdup(remote_addr->rpc_addr);
  // notifications subscription optional
  if (remote_addr && remote_addr->notifications_addr)
    notifications_addr = strdup(remote_addr->notifications_addr);
}

static void free_addrs() {
  free(rpc_addr);
  if (notifications_addr) free(notifications_addr);
}

extern pi_status_t notifications_start(const char *);

pi_status_t _pi_init(void *extra) {
  assert(!state.init);
  init_addrs((pi_remote_addr_t *)extra);
  state.s = nn_socket(AF_SP, NN_REQ);
  if (state.s < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  if (nn_connect(state.s, rpc_addr) < 0) return PI_STATUS_RPC_CONNECT_ERROR;
  state.init = 1;

  pi_status_t status;

  if (notifications_addr) {
    status = notifications_start(notifications_addr);
    if (status != PI_STATUS_SUCCESS) return status;
  }

  req_hdr_t req;
  pi_rpc_id_t req_id = state.req_id++;
  emit_req_hdr((char *)&req, req_id, PI_RPC_INIT);

  int rc = nn_send(state.s, (char *)&req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  char *rep = NULL;
  int bytes = nn_recv(state.s, &rep, NN_MSG, 0);
  if (bytes <= 0) return PI_STATUS_RPC_TRANSPORT_ERROR;

  char *rep_ = rep;
  status = retrieve_rep_hdr(rep_, req_id);
  if (status != PI_STATUS_SUCCESS) {
    nn_freemsg(rep);
    return status;
  }
  rep_ += sizeof(rep_hdr_t);

  process_state_sync(rep_);

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_dev_id_t dev_id;
  } hdr_t;
  char *p4info_json = strdup("\0");
  if (p4info) p4info_json = pi_serialize_config(p4info, 0);
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
  if ((size_t)rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_update_device_start(pi_dev_id_t dev_id,
                                    const pi_p4info_t *p4info,
                                    const char *device_data,
                                    size_t device_data_size) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_dev_id_t dev_id;
  } hdr_t;
  char *p4info_json = pi_serialize_config(p4info, 0);
  size_t p4info_size = strlen(p4info_json) + 1;
  size_t s = sizeof(hdr_t) + p4info_size + sizeof(uint32_t) + device_data_size;
  char *req = nn_allocmsg(s, 0);
  char *req_ = req;

  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_UPDATE_DEVICE_START);
  req_ += emit_dev_id(req_, dev_id);
  memcpy(req_, p4info_json, p4info_size);
  req_ += p4info_size;
  free(p4info_json);
  req_ += emit_uint32(req_, device_data_size);
  memcpy(req_, device_data, device_data_size);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t)rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_update_device_end(pi_dev_id_t dev_id) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_dev_id_t dev_id;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_UPDATE_DEVICE_END);
  req_ += emit_dev_id(req_, dev_id);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_remove_device(pi_dev_id_t dev_id) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;
  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_dev_id_t dev_id;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
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
  emit_req_hdr((char *)&req, req_id, PI_RPC_DESTROY);

  int rc = nn_send(state.s, (char *)&req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  free_addrs();

  return wait_for_status(req_id);
}

pi_status_t _pi_session_init(pi_session_handle_t *session_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  req_hdr_t req;
  pi_rpc_id_t req_id = state.req_id++;
  emit_req_hdr((char *)&req, req_id, PI_RPC_SESSION_INIT);

  int rc = nn_send(state.s, (char *)&req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  typedef struct __attribute__((packed)) {
    rep_hdr_t hdr;
    s_pi_session_handle_t h;
  } rep_t;
  rep_t rep;
  rc = nn_recv(state.s, &rep, sizeof(rep), 0);
  if (rc != sizeof(rep)) return PI_STATUS_RPC_TRANSPORT_ERROR;
  pi_status_t status = retrieve_rep_hdr((char *)&rep, req_id);
  // condition on success?
  retrieve_session_handle((char *)&rep.h, session_handle);
  return status;
}

pi_status_t _pi_session_cleanup(pi_session_handle_t session_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t h;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_SESSION_CLEANUP);
  req_ += emit_session_handle(req_, session_handle);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_batch_begin(pi_session_handle_t session_handle) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t h;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_BATCH_BEGIN);
  req_ += emit_session_handle(req_, session_handle);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_batch_end(pi_session_handle_t session_handle, bool hw_sync) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  typedef struct __attribute__((packed)) {
    req_hdr_t hdr;
    s_pi_session_handle_t h;
    uint32_t hw_sync;
  } req_t;
  req_t req;
  char *req_ = (char *)&req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_BATCH_END);
  req_ += emit_session_handle(req_, session_handle);
  req_ += emit_uint32(req_, hw_sync);

  int rc = nn_send(state.s, &req, sizeof(req), 0);
  if (rc != sizeof(req)) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}

pi_status_t _pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                               size_t size) {
  if (!state.init) return PI_STATUS_RPC_NOT_INIT;

  size_t s = 0;
  s += sizeof(req_hdr_t);
  s += sizeof(s_pi_dev_id_t);
  s += sizeof(uint32_t);
  s += size;

  char *req = nn_allocmsg(s, 0);
  char *req_ = req;
  pi_rpc_id_t req_id = state.req_id++;
  req_ += emit_req_hdr(req_, req_id, PI_RPC_PACKETOUT_SEND);
  req_ += emit_dev_id(req_, dev_id);
  req_ += emit_uint32(req_, size);
  memcpy(req_, pkt, size);

  int rc = nn_send(state.s, &req, NN_MSG, 0);
  if ((size_t)rc != s) return PI_STATUS_RPC_TRANSPORT_ERROR;

  return wait_for_status(req_id);
}
