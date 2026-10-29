/* Copyright 2026 Lorenzo Rinieri
 * SPDX-License-Identifier: Apache-2.0
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

#include <PI/target/pi_register_imp.h>

pi_status_t _pi_register_read(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                              size_t index, char *value) {
  (void)session_handle;
  (void)dev_tgt;
  (void)register_id;
  (void)index;
  (void)value;
  return PI_STATUS_RPC_NOT_IMPLEMENTED;
}

pi_status_t _pi_register_write(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                               size_t index, const char *value) {
  (void)session_handle;
  (void)dev_tgt;
  (void)register_id;
  (void)index;
  (void)value;
  return PI_STATUS_RPC_NOT_IMPLEMENTED;
}

pi_status_t _pi_register_write_all(pi_session_handle_t session_handle,
                                   pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                                   const char *value) {
  (void)session_handle;
  (void)dev_tgt;
  (void)register_id;
  (void)value;
  return PI_STATUS_RPC_NOT_IMPLEMENTED;
}
