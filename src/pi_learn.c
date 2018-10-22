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
#include "_assert.h"
#include "pi_learn_int.h"

#include <pthread.h>
#include <stdlib.h>

#include "device_map.h"
#include "vector.h"

typedef struct {
  PILearnCb cb;
  void *cookie;
} cb_data_t;

static device_map_t device_cbs;

static PILearnCb default_cb;
static void *default_cb_cookie;

static pthread_mutex_t cb_mutex;

static cb_data_t *find_cb(pi_dev_id_t dev_id) {
  return (cb_data_t *)device_map_get(&device_cbs, dev_id);
}

static void add_cb(pi_dev_id_t dev_id, PILearnCb cb, void *cb_cookie) {
  cb_data_t *cb_data = find_cb(dev_id);
  if (cb_data == NULL) {
    cb_data = malloc(sizeof(cb_data_t));
    _PI_ASSERT(device_map_add(&device_cbs, dev_id, cb_data));
  }
  cb_data->cb = cb;
  cb_data->cookie = cb_cookie;
  return;
}

static void rm_cb(pi_dev_id_t dev_id) {
  cb_data_t *cb_data = find_cb(dev_id);
  if (cb_data != NULL) {
    _PI_ASSERT(device_map_remove(&device_cbs, dev_id));
    free(cb_data);
  }
}

pi_status_t pi_learn_init() {
  if (pthread_mutex_init(&cb_mutex, NULL)) return PI_STATUS_PTHREAD_ERROR;
  device_map_create(&device_cbs);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_destroy() {
  if (pthread_mutex_destroy(&cb_mutex)) return PI_STATUS_PTHREAD_ERROR;
  device_map_destroy(&device_cbs);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_assign_device(pi_dev_id_t dev_id) {
  (void)dev_id;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_remove_device(pi_dev_id_t dev_id) {
  return pi_learn_deregister_cb(dev_id);
}

pi_status_t pi_learn_register_cb(pi_dev_id_t dev_id, PILearnCb cb,
                                 void *cb_cookie) {
  pthread_mutex_lock(&cb_mutex);
  add_cb(dev_id, cb, cb_cookie);
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_register_default_cb(PILearnCb cb, void *cb_cookie) {
  pthread_mutex_lock(&cb_mutex);
  default_cb = cb;
  default_cb_cookie = cb_cookie;
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_deregister_cb(pi_dev_id_t dev_id) {
  pthread_mutex_lock(&cb_mutex);
  rm_cb(dev_id);
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_deregister_default_cb() {
  pthread_mutex_lock(&cb_mutex);
  default_cb = NULL;
  default_cb_cookie = NULL;
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_learn_config_set(pi_session_handle_t session_handle,
                                pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                const pi_learn_config_t *config) {
  return _pi_learn_config_set(session_handle, dev_id, learn_id, config);
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
  pthread_mutex_lock(&cb_mutex);
  cb_data_t *cb_data = find_cb(dev_id);
  if (cb_data) {
    cb_data->cb(msg, cb_data->cookie);
    pthread_mutex_unlock(&cb_mutex);
    return PI_STATUS_SUCCESS;
  }
  if (default_cb) {
    default_cb(msg, default_cb_cookie);
    pthread_mutex_unlock(&cb_mutex);
    return PI_STATUS_SUCCESS;
  }
  pthread_mutex_unlock(&cb_mutex);
  return PI_STATUS_LEARN_NO_MATCHING_CB;
}
