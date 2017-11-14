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

#include <PI/pi_learn.h>
#include <PI/target/pi_learn_imp.h>

#include <assert.h>
#include <stdlib.h>

#include "device_map.h"
#include "vector.h"

typedef struct {
  pi_p4_id_t learn_id;
  PILearnCb cb;
  void *cookie;
} cb_data_t;

// map of vector_t *
// hack in the absence of init function
// TODO(antonin): proper initialization and cleanup, including when a device is
// assigned / removed
static device_map_t device_cbs = {NULL};

static PILearnCb default_cb;
static void *default_cb_cookie;

static cb_data_t *find_cb(pi_dev_id_t dev_id, pi_p4_id_t learn_id) {
  vector_t *cbs = (vector_t *)device_map_get(&device_cbs, dev_id);
  if (!cbs) return NULL;
  cb_data_t *cb_data = vector_data(cbs);
  size_t num_cbs = vector_size(cbs);
  for (size_t i = 0; i < num_cbs; i++)
    if (cb_data[i].learn_id == learn_id) return &cb_data[i];
  return NULL;
}

static void add_cb(pi_dev_id_t dev_id, pi_p4_id_t learn_id, PILearnCb cb,
                   void *cb_cookie) {
  cb_data_t *cb_data = find_cb(dev_id, learn_id);
  if (cb_data) {
    cb_data->cb = cb;
    cb_data->cookie = cb_cookie;
    return;
  }
  vector_t *cbs = (vector_t *)device_map_get(&device_cbs, dev_id);
  if (!cbs) {
    cbs = vector_create(sizeof(cb_data_t), 8);
    device_map_add(&device_cbs, dev_id, cbs);
  }
  cb_data_t new_cb_data = {learn_id, cb, cb_cookie};
  vector_push_back(cbs, &new_cb_data);
}

static void rm_cb(pi_dev_id_t dev_id, pi_p4_id_t learn_id) {
  cb_data_t *cb_data = find_cb(dev_id, learn_id);
  if (!cb_data) return;
  vector_t *cbs = (vector_t *)device_map_get(&device_cbs, dev_id);
  assert(cbs);
  vector_remove_e(cbs, cb_data);
  if (vector_size(cbs) == 0) {
    vector_destroy(cbs);
    device_map_remove(&device_cbs, dev_id);
  }
}

pi_status_t pi_learn_register_cb(pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                 PILearnCb cb, void *cb_cookie) {
  add_cb(dev_id, learn_id, cb, cb_cookie);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_register_default_cb(PILearnCb cb, void *cb_cookie) {
  default_cb = cb;
  default_cb_cookie = cb_cookie;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_deregister_cb(pi_dev_id_t dev_id, pi_p4_id_t learn_id) {
  rm_cb(dev_id, learn_id);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_deregister_default_cb() {
  default_cb = NULL;
  default_cb_cookie = NULL;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_msg_ack(pi_session_handle_t session_handle,
                             pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                             pi_learn_msg_id_t msg_id) {
  return _pi_learn_msg_ack(session_handle, dev_id, learn_id, msg_id);
}

pi_status_t pi_learn_msg_done(pi_learn_msg_t *msg) {
  return _pi_learn_msg_done(msg);
}

// called by backend
pi_status_t pi_learn_new_msg(pi_learn_msg_t *msg) {
  pi_dev_id_t dev_id = msg->dev_tgt.dev_id;
  cb_data_t *cb_data = find_cb(dev_id, msg->learn_id);
  if (cb_data) {
    cb_data->cb(msg, cb_data->cookie);
    return PI_STATUS_SUCCESS;
  }
  if (default_cb) {
    default_cb(msg, default_cb_cookie);
    return PI_STATUS_SUCCESS;
  }
  return PI_STATUS_LEARN_NO_MATCHING_CB;
}
