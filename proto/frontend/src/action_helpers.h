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

#ifndef SRC_ACTION_HELPERS_H_
#define SRC_ACTION_HELPERS_H_

#include <PI/pi.h>

#include "google/rpc/status.pb.h"

namespace p4 {

class Action;

}  // namespace p4

namespace pi {

namespace fe {

namespace proto {

using Status = ::google::rpc::Status;

Status validate_action_data(pi_p4info_t *p4info, const p4::Action &action);

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_ACTION_HELPERS_H_
