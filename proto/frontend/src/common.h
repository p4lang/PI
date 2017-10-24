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

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

#include <PI/pi.h>

#include <string>

#include "google/rpc/code.pb.h"
#include "google/rpc/status.pb.h"

namespace pi {

namespace fe {

namespace proto {

using Code = ::google::rpc::Code;
using Status = ::google::rpc::Status;

namespace common {

struct SessionTemp {
  explicit SessionTemp(bool batch = false)
      : batch(batch) {
    pi_session_init(&sess);
    if (batch) pi_batch_begin(sess);
  }

  ~SessionTemp() {
    if (batch) pi_batch_end(sess, true  /* hw_sync */);
    pi_session_cleanup(sess);
  }

  pi_session_handle_t get() const { return sess; }

  pi_session_handle_t sess;
  bool batch;
};

Code check_proto_bytestring(const std::string &str, size_t nbits);

std::string range_default_lo(size_t nbits);
std::string range_default_hi(size_t nbits);

inline Status make_invalid_p4_id_status() {
  Status status;
  status.set_code(Code::INVALID_ARGUMENT);
  status.set_message("Invalid P4 id");
  return status;
}

}  // namespace common

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_COMMON_H_
