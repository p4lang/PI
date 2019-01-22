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

#include "action_helpers.h"
#include "common.h"

#include "google/rpc/code.pb.h"
#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

namespace p4v1 = ::p4::v1;

namespace pi {

namespace fe {

namespace proto {

using Code = ::google::rpc::Code;
using common::check_proto_bytestring;

Status validate_action_data(const pi_p4info_t *p4info,
                            const p4v1::Action &action) {
  Status status;
  Code code;
  size_t exp_num_params = pi_p4info_action_num_params(
      p4info, action.action_id());
  if (static_cast<size_t>(action.params().size()) != exp_num_params) {
    status.set_code(Code::INVALID_ARGUMENT);
    return status;
  }
  for (const auto &p : action.params()) {
    auto not_found = static_cast<size_t>(-1);
    size_t bitwidth = pi_p4info_action_param_bitwidth(
        p4info, action.action_id(), p.param_id());
    if (bitwidth == not_found) {
      status.set_code(Code::INVALID_ARGUMENT);
      return status;
    }
    if ((code = check_proto_bytestring(p.value(), bitwidth)) != Code::OK) {
      status.set_code(code);
      return status;
    }
  }
  return status;
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
