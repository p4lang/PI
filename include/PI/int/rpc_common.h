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

#ifndef PI_INT_RPC_COMMON_H_
#define PI_INT_RPC_COMMON_H_

typedef enum {
  PI_RPC_INIT,
  PI_RPC_ASSIGN_DEVICE,
  PI_RPC_REMOVE_DEVICE,
  PI_RPC_DESTROY
} pi_rpc_msg_id_t;

#endif  // PI_INT_RPC_COMMON_H_
