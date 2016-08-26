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

#include "vector.h"

#define MAX_DEVICES 256

typedef struct {
  pi_p4_id_t learn_id;
  PILearnCb cb;
  void *cookie;
} cb_data_t;

typedef struct { vector_t *cbs; } one_device_cbs_t;

static one_device_cbs_t device_cbs[MAX_DEVICES];

static PILearnCb default_cb;
static void *default_cb_cookie;

static cb_data_t *find_cb(pi_dev_id_t dev_id, pi_p4_id_t learn_id) {
  one_device_cbs_t *dcbs = &device_cbs[dev_id];
  if (!dcbs->cbs) return NULL;
  cb_data_t *cb_data = vector_data(dcbs->cbs);
  size_t num_cbs = vector_size(dcbs->cbs);
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
  one_device_cbs_t *dcbs = &device_cbs[dev_id];
  if (!dcbs->cbs) dcbs->cbs = vector_create(sizeof(cb_data_t), 8);
  cb_data_t new_cb_data = {learn_id, cb, cb_cookie};
  vector_push_back(dcbs->cbs, &new_cb_data);
}

static void rm_cb(pi_dev_id_t dev_id, pi_p4_id_t learn_id) {
  cb_data_t *cb_data = find_cb(dev_id, learn_id);
  if (!cb_data) return;
  one_device_cbs_t *dcbs = &device_cbs[dev_id];
  vector_remove_e(dcbs->cbs, cb_data);
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
