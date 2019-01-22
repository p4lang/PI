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

#include <memory>
#include <string>
#include <vector>

#include "google/rpc/code.pb.h"
#include "google/rpc/status.pb.h"

#include "report_error.h"

namespace pi {

namespace fe {

namespace proto {

using Code = ::google::rpc::Code;
using Status = ::google::rpc::Status;

namespace common {

using p4_id_t = uint32_t;

struct SessionTemp;

struct LocalCleanupIface {
  virtual ~LocalCleanupIface() { }

  virtual Status cleanup(const SessionTemp &session) = 0;
  virtual void cancel() = 0;
};

// SessionTemp is used to manage a P4Runtime WriteRequest message. All
// operations in the message are executed as part of the same PI batch, the
// SessionTemp destructor will block until all operations have been completed in
// HW.
// SessionTemp also has a mechanism to perform some low-level cleanup tasks in
// case of an unexpected error during an unexpected error (in the lower layers
// of the stack). For example, when using one-shot action selector programming
// for an indirect table, a single P4Runtime update may map to many PI calls. If
// one of these calls fail, it may be desirable to undo all previous PI
// calls. This isn't as powerful as the P4Runtime semantics (not implemented
// yet), but should be ok for simple things like action profile programming. If
// one of the rollback / cleanup operations fail, we return a (serious) INTERNAL
// error.
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

  Status local_cleanup() {
    int error_cnt = 0;
    Status status;
    for (auto task_it = cleanup_tasks.rbegin();
         task_it != cleanup_tasks.rend();
         ++task_it) {
      status = (*task_it)->cleanup(*this);
      if (IS_ERROR(status)) error_cnt++;
    }
    cleanup_tasks.clear();
    cleanup_scopes.clear();
    if (error_cnt == 0) RETURN_OK_STATUS();
    if (error_cnt == 1) return status;
    RETURN_ERROR_STATUS(
        Code::INTERNAL,
        "{} serious errors when encountered during cleanup; you may need to "
        "reboot the device");
  }

  void cleanup_scope_push() {
    cleanup_scopes.push_back(cleanup_tasks.size());
  }

  void cleanup_scope_pop() {
    cleanup_tasks.resize(cleanup_scopes.back());
    cleanup_scopes.pop_back();
  }

  LocalCleanupIface *cleanup_task_push(
      std::unique_ptr<LocalCleanupIface> task) {
    cleanup_tasks.push_back(std::move(task));
    return cleanup_tasks.back().get();
  }

  LocalCleanupIface *cleanup_task_back() {
    return cleanup_tasks.back().get();
  }

  pi_session_handle_t sess;
  bool batch;
  std::vector<std::unique_ptr<LocalCleanupIface> > cleanup_tasks;
  std::vector<size_t> cleanup_scopes;
};

Code check_proto_bytestring(const std::string &str, size_t nbits);

bool check_prefix_trailing_zeros(const std::string &str, int pLen);

std::string range_default_lo(size_t nbits);
std::string range_default_hi(size_t nbits);

inline Status make_invalid_p4_id_status() {
  RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT, "Invalid P4 id");
}

}  // namespace common

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_COMMON_H_
