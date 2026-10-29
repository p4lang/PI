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
//
// When the P4Info comes from P4Runtime, the cells of a register can have any
// P4 type, and the value is laid out in the bitwidth bits of the cell as
// follows, starting from the most significant bit:
//  - bit<W>: W bits.
//  - int<W>: W bits, in 2's complement.
//  - bool: 1 bit, set for true.
//  - serializable enum: the value of the underlying type bit<W>.
//  - enum without an underlying type, error: the index of the member in the
//    P4Info, as a bit<32>. This is how p4c represents enums, numbering the
//    members in declaration order.
//  - varbit<M>: the dynamic bitwidth as a bit<32>, followed by the value on M
//    bits.
//  - struct, tuple: the members, in order.
//  - header: the validity bit (set if the header is valid), followed by the
//    fields, in order. The fields of an invalid header are written as 0.
//  - header union: the headers, in order.
//  - header stack, header union stack: the elements, starting from index 0.
//  - type declaration (new type): the original type.
// For example, the cells of a register<h_t>, with
//   header h_t { bit<8> a; int<4> b; }
// have 13 bits: the validity bit, followed by a and then by b. Types with a
// @p4runtime_translation annotation, headers with a varbit field and types
// whose values have 0 bits are not supported (bitwidth is 0).

//! Reads the cell at the given \p index of a register array. \p value must
//! point to a buffer large enough to hold one cell.
pi_status_t pi_register_read(pi_session_handle_t session_handle,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                             size_t index, char *value);

//! Writes the cell at the given \p index of a register array.
pi_status_t pi_register_write(pi_session_handle_t session_handle,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                              size_t index, const char *value);

//! Writes the same value to all the cells of a register array. The write is
//! atomic with respect to the data plane: an action which accesses the register
//! array sees either the old value or the new one in all the cells.
pi_status_t pi_register_write_all(pi_session_handle_t session_handle,
                                  pi_dev_tgt_t dev_tgt, pi_p4_id_t register_id,
                                  const char *value);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_REGISTER_H_
