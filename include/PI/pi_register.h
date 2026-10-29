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

//! @file

#ifndef PI_INC_PI_PI_REGISTER_H_
#define PI_INC_PI_PI_REGISTER_H_

#include <PI/pi_base.h>

#ifdef __cplusplus
extern "C" {
#endif

// The value of a register cell is a byte array in network byte order, of size
// (bitwidth + 7) / 8, where bitwidth is given by
// pi_p4info_register_get_bitwidth. This is the same format as the one used for
// match keys and action data.

//! Reads the cell at the given \p index of a register array. \p value must
//! point to a buffer large enough to hold one cell.
pi_status_t pi_register_read(pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                             size_t index, char *value);

//! Writes the cell at the given \p index of a register array.
pi_status_t pi_register_write(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                              size_t index, const char *value);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_REGISTER_H_
