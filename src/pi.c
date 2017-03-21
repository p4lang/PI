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

#include "PI/pi.h"
#include "PI/int/pi_int.h"
#include "PI/int/serialize.h"
#include "PI/target/pi_imp.h"
#include "utils/logging.h"

#include <stdlib.h>
#include <string.h>

#define MAX_DEVICES 256

static size_t num_devices;
static pi_device_info_t *device_mapping;

typedef struct {
  int is_set;
  PIDirectResMsgSizeFn msg_size_fn;
  PIDirectResEmitFn emit_fn;
  size_t size_of;
  PIDirectResRetrieveFn retrieve_fn;
} pi_direct_res_rpc_t;

// allocate at runtime?
static pi_direct_res_rpc_t direct_res_rpc[PI_RES_TYPE_MAX];

typedef struct {
  PIPacketInCb cb;
  void *cookie;
} packetin_cb_data_t;

static packetin_cb_data_t device_packetin_cb_data[MAX_DEVICES];
static packetin_cb_data_t default_packetin_cb_data;

pi_device_info_t *pi_get_device_info(pi_dev_id_t dev_id) {
  return device_mapping + dev_id;
}

pi_device_info_t *pi_get_devices(size_t *nb) {
  *nb = num_devices;
  return device_mapping;
}

const pi_p4info_t *pi_get_device_p4info(pi_dev_id_t dev_id) {
  return device_mapping[dev_id].p4info;
}

static size_t direct_res_counter_msg_size(const void *config) {
  (void)config;
  return sizeof(s_pi_counter_data_t);
}

static size_t direct_res_counter_emit(char *dst, const void *config) {
  return emit_counter_data(dst, (const pi_counter_data_t *)config);
}

static size_t direct_res_counter_retrieve(const char *src, void *config) {
  return retrieve_counter_data(src, (pi_counter_data_t *)config);
}

static size_t direct_res_meter_msg_size(const void *config) {
  (void)config;
  return sizeof(s_pi_meter_spec_t);
}

static size_t direct_res_meter_emit(char *dst, const void *config) {
  return emit_meter_spec(dst, (const pi_meter_spec_t *)config);
}

static size_t direct_res_meter_retrieve(const char *src, void *config) {
  return retrieve_meter_spec(src, (pi_meter_spec_t *)config);
}

static void register_std_direct_res() {
  pi_status_t status;
  status = pi_direct_res_register(
      PI_COUNTER_ID, direct_res_counter_msg_size, direct_res_counter_emit,
      sizeof(pi_counter_data_t), direct_res_counter_retrieve);
  assert(status == PI_STATUS_SUCCESS);
  status = pi_direct_res_register(
      PI_METER_ID, direct_res_meter_msg_size, direct_res_meter_emit,
      sizeof(pi_meter_spec_t), direct_res_meter_retrieve);
  assert(status == PI_STATUS_SUCCESS);
}

pi_status_t pi_init(size_t max_devices, pi_remote_addr_t *remote_addr) {
  // TODO(antonin): best place for this? I don't see another option
  register_std_direct_res();
  num_devices = max_devices;
  device_mapping = calloc(max_devices, sizeof(pi_device_info_t));
  return _pi_init((void *)remote_addr);
}

void pi_update_device_config(pi_dev_id_t dev_id, const pi_p4info_t *p4info) {
  pi_device_info_t *info = &device_mapping[dev_id];
  info->version++;
  info->p4info = p4info;
}

void pi_reset_device_config(pi_dev_id_t dev_id) {
  pi_device_info_t *info = &device_mapping[dev_id];
  memset(info, 0, sizeof(*info));
}

pi_status_t pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                             pi_assign_extra_t *extra) {
  if (dev_id >= num_devices) return PI_STATUS_DEV_OUT_OF_RANGE;

  pi_device_info_t *info = &device_mapping[dev_id];
  if (info->version) return PI_STATUS_DEV_ALREADY_ASSIGNED;

  pi_status_t status = _pi_assign_device(dev_id, p4info, extra);
  if (status == PI_STATUS_SUCCESS) pi_update_device_config(dev_id, p4info);

  return status;
}

pi_status_t pi_update_device_start(pi_dev_id_t dev_id,
                                   const pi_p4info_t *p4info,
                                   const char *device_data,
                                   size_t device_data_size) {
  pi_status_t status =
      _pi_update_device_start(dev_id, p4info, device_data, device_data_size);
  if (status == PI_STATUS_SUCCESS) pi_update_device_config(dev_id, p4info);

  return status;
}

pi_status_t pi_update_device_end(pi_dev_id_t dev_id) {
  return _pi_update_device_end(dev_id);
}

bool pi_is_device_assigned(pi_dev_id_t dev_id) {
  if (dev_id >= num_devices) return false;
  pi_device_info_t *info = &device_mapping[dev_id];
  return info->version;
}

pi_status_t pi_remove_device(pi_dev_id_t dev_id) {
  if (dev_id >= num_devices) return PI_STATUS_DEV_OUT_OF_RANGE;

  pi_device_info_t *info = &device_mapping[dev_id];
  if (!info->version) return PI_STATUS_DEV_NOT_ASSIGNED;

  pi_status_t status = _pi_remove_device(dev_id);
  if (status == PI_STATUS_SUCCESS) pi_reset_device_config(dev_id);

  return status;
}

pi_status_t pi_session_init(pi_session_handle_t *session_handle) {
  return _pi_session_init(session_handle);
}

pi_status_t pi_session_cleanup(pi_session_handle_t session_handle) {
  return _pi_session_cleanup(session_handle);
}

pi_status_t pi_batch_begin(pi_session_handle_t session_handle) {
  return _pi_batch_begin(session_handle);
}

pi_status_t pi_batch_end(pi_session_handle_t session_handle, bool hw_sync) {
  return _pi_batch_end(session_handle, hw_sync);
}

pi_status_t pi_destroy() {
  free(device_mapping);
  device_mapping = NULL;
  num_devices = 0;
  return _pi_destroy();
}

bool pi_is_action_id(pi_p4_id_t id) {
  return PI_GET_TYPE_ID(id) == PI_ACTION_ID;
}

bool pi_is_table_id(pi_p4_id_t id) { return PI_GET_TYPE_ID(id) == PI_TABLE_ID; }

bool pi_is_act_prof_id(pi_p4_id_t id) {
  return PI_GET_TYPE_ID(id) == PI_ACT_PROF_ID;
}

bool pi_is_counter_id(pi_p4_id_t id) {
  return PI_GET_TYPE_ID(id) == PI_COUNTER_ID;
}

bool pi_is_meter_id(pi_p4_id_t id) { return PI_GET_TYPE_ID(id) == PI_METER_ID; }

pi_status_t pi_direct_res_register(pi_res_type_id_t res_type,
                                   PIDirectResMsgSizeFn msg_size_fn,
                                   PIDirectResEmitFn emit_fn, size_t size_of,
                                   PIDirectResRetrieveFn retrieve_fn) {
  if (res_type >= PI_RES_TYPE_MAX) return PI_STATUS_INVALID_RES_TYPE_ID;
  direct_res_rpc[res_type].is_set = 1;
  direct_res_rpc[res_type].msg_size_fn = msg_size_fn;
  direct_res_rpc[res_type].emit_fn = emit_fn;
  direct_res_rpc[res_type].size_of = size_of;
  direct_res_rpc[res_type].retrieve_fn = retrieve_fn;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_direct_res_get_fns(pi_res_type_id_t res_type,
                                  PIDirectResMsgSizeFn *msg_size_fn,
                                  PIDirectResEmitFn *emit_fn, size_t *size_of,
                                  PIDirectResRetrieveFn *retrieve_fn) {
  if (res_type >= PI_RES_TYPE_MAX) return PI_STATUS_INVALID_RES_TYPE_ID;
  if (!direct_res_rpc[res_type].is_set) return PI_STATUS_INVALID_RES_TYPE_ID;
  if (msg_size_fn) *msg_size_fn = direct_res_rpc[res_type].msg_size_fn;
  if (emit_fn) *emit_fn = direct_res_rpc[res_type].emit_fn;
  if (size_of) *size_of = direct_res_rpc[res_type].size_of;
  if (retrieve_fn) *retrieve_fn = direct_res_rpc[res_type].retrieve_fn;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetin_register_cb(pi_dev_id_t dev_id, PIPacketInCb cb,
                                    void *cb_cookie) {
  if (dev_id >= MAX_DEVICES) return PI_STATUS_DEV_OUT_OF_RANGE;
  packetin_cb_data_t *packetin_cb_data = &device_packetin_cb_data[dev_id];
  packetin_cb_data->cb = cb;
  packetin_cb_data->cookie = cb_cookie;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetin_register_default_cb(PIPacketInCb cb, void *cb_cookie) {
  default_packetin_cb_data.cb = cb;
  default_packetin_cb_data.cookie = cb_cookie;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetin_deregister_cb(pi_dev_id_t dev_id) {
  if (dev_id >= MAX_DEVICES) return PI_STATUS_DEV_OUT_OF_RANGE;
  packetin_cb_data_t *packetin_cb_data = &device_packetin_cb_data[dev_id];
  packetin_cb_data->cb = NULL;
  packetin_cb_data->cookie = NULL;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetin_deregister_default_cb() {
  default_packetin_cb_data.cb = NULL;
  default_packetin_cb_data.cookie = NULL;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                              size_t size) {
  return _pi_packetout_send(dev_id, pkt, size);
}

pi_status_t pi_packetin_receive(pi_dev_id_t dev_id, const char *pkt,
                                size_t size) {
  assert(dev_id < MAX_DEVICES);
  packetin_cb_data_t *packetin_cb_data = &device_packetin_cb_data[dev_id];
  if (packetin_cb_data->cb) {
    packetin_cb_data->cb(dev_id, pkt, size, packetin_cb_data->cookie);
    return PI_STATUS_SUCCESS;
  } else if (default_packetin_cb_data.cb) {
    default_packetin_cb_data.cb(dev_id, pkt, size,
                                default_packetin_cb_data.cookie);
    return PI_STATUS_SUCCESS;
  }
  return PI_STATUS_PACKETIN_NO_CB;
}
