/* Copyright 2018-present Barefoot Networks, Inc.
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

#include <PI/pi_clone.h>
#include <PI/pi_mc.h>
#include <PI/target/pi_clone_imp.h>

#include "func_counter.h"

pi_status_t _pi_clone_session_set(
    pi_session_handle_t session_handle, pi_dev_tgt_t dev_tgt,
    pi_clone_session_id_t clone_session_id,
    const pi_clone_session_config_t *clone_session_config) {
  (void)session_handle;
  (void)dev_tgt;
  (void)clone_session_id;
  (void)clone_session_config;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_clone_session_reset(pi_session_handle_t session_handle,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_clone_session_id_t clone_session_id) {
  (void)session_handle;
  (void)dev_tgt;
  (void)clone_session_id;
  func_counter_increment(__func__);
  return PI_STATUS_SUCCESS;
}
