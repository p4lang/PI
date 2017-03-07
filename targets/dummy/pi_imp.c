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

#include <PI/pi.h>
#include <PI/target/pi_imp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "func_counter.h"

static char *counter_dump_path = NULL;

pi_status_t _pi_init(void *extra) {
  if (extra)
    counter_dump_path = strdup((const char *)extra);
  else
    counter_dump_path = strdup("func_counter.txt");
  func_counter_init();
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra) {
  (void)dev_id;
  (void)p4info;
  (void)extra;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_update_device_start(pi_dev_id_t dev_id,
                                    const pi_p4info_t *p4info,
                                    const char *device_data,
                                    size_t device_data_size) {
  (void)dev_id;
  (void)p4info;
  (void)device_data;
  (void)device_data_size;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_update_device_end(pi_dev_id_t dev_id) {
  (void)dev_id;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_remove_device(pi_dev_id_t dev_id) {
  (void)dev_id;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_destroy() {
  func_counter_increment(__func__);
  if (counter_dump_path) {
    func_counter_dump_to_file(counter_dump_path);
    free(counter_dump_path);
    counter_dump_path = NULL;
  }
  func_counter_destroy();
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_session_init(pi_session_handle_t *session_handle) {
  *session_handle = 0;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_session_cleanup(pi_session_handle_t session_handle) {
  (void)session_handle;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_batch_begin(pi_session_handle_t session_handle) {
  (void)session_handle;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_batch_end(pi_session_handle_t session_handle, bool hw_sync) {
  (void)session_handle;
  (void)hw_sync;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                               size_t size) {
  (void)dev_id;
  (void)pkt;
  (void)size;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}
