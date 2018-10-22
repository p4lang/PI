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

#include <PI/target/pi_learn_imp.h>

#include <stdio.h>

#include "func_counter.h"

pi_status_t _pi_learn_config_set(pi_session_handle_t session_handle,
                                 pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                 const pi_learn_config_t *config) {
  (void)session_handle;
  (void)dev_id;
  (void)learn_id;
  (void)config;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_learn_msg_ack(pi_session_handle_t session_handle,
                              pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                              pi_learn_msg_id_t msg_id) {
  (void)session_handle;
  (void)dev_id;
  (void)learn_id;
  (void)msg_id;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_learn_msg_done(pi_learn_msg_t *msg) {
  (void)msg;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}
