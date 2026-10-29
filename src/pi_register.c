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

#include <PI/p4info.h>
#include <PI/pi.h>
#include <PI/pi_register.h>
#include <PI/target/pi_register_imp.h>

static pi_status_t check_register_access(pi_dev_tgt_t dev_tgt,
                                         pi_p4_id_t register_id, size_t index) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.dev_id);
  if (!p4info) return PI_STATUS_DEV_NOT_ASSIGNED;
  if (!pi_is_register_id(register_id) ||
      !pi_p4info_is_valid_id(p4info, register_id))
    return PI_STATUS_NETV_INVALID_OBJ_ID;
  if (pi_p4info_register_get_bitwidth(p4info, register_id) == 0)
    return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
  if (index >= pi_p4info_register_get_size(p4info, register_id))
    return PI_STATUS_OUT_OF_BOUND_IDX;
  return PI_STATUS_SUCCESS;
}

pi_status_t pi_register_read(pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                             size_t index, char *value) {
  pi_status_t status = check_register_access(dev_tgt, register_id, index);
  if (status != PI_STATUS_SUCCESS) return status;
  return _pi_register_read(session_handle, dev_tgt, register_id, index, value);
}

pi_status_t pi_register_write(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                              size_t index, const char *value) {
  pi_status_t status = check_register_access(dev_tgt, register_id, index);
  if (status != PI_STATUS_SUCCESS) return status;
  return _pi_register_write(session_handle, dev_tgt, register_id, index, value);
}
