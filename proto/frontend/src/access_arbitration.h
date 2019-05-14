/* Copyright 2019-present Barefoot Networks, Inc.
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

#ifndef SRC_ACCESS_ARBITRATION_H_
#define SRC_ACCESS_ARBITRATION_H_

#include <PI/p4info.h>
#include <PI/proto/util.h>

#include <condition_variable>
#include <mutex>
#include <set>

#include "common.h"

namespace p4 {
namespace v1 {
class WriteRequest;
}  // namespace v1
}  // namespace p4

namespace pi {

namespace fe {

namespace proto {

// Arbitrates access between different concurrent RPCs. There are 4 different
// levels of access:
//   * UniqueAccess: exclusive, no concurrent access possible
//   * WriteAccess: exclusive access to a specific set of P4Info objects
//   * ReadAccess: shared access to the entire set of P4Info objects; other
//     ReadAccess instances can exist concurrently, and so can NoWriteAccess
//     instances, but it is not possible to have a concurrent WriteAccess
//     instance
//   * NoWriteAccess: access to a specific P4Info object that tolerates
//     concurrent ReadAccess instances, but not concurrent WriteAccess /
//     NoWriteAccess instances with an overlapping subset of P4Info objects
class AccessArbitration {
 public:
  class Access {
   protected:
    explicit Access(AccessArbitration *arbitrator);
    ~Access();

    AccessArbitration *arbitrator;
  };

  class WriteAccess : public Access {
   public:
    ~WriteAccess();

   private:
    friend class AccessArbitration;
    explicit WriteAccess(AccessArbitration *arbitrator);
    std::set<common::p4_id_t> p4_ids;
  };

  class ReadAccess : public Access {
   public:
    ~ReadAccess();

   private:
    friend class AccessArbitration;
    explicit ReadAccess(AccessArbitration *arbitrator);
  };

  class NoWriteAccess : public Access {
   public:
    ~NoWriteAccess();

   private:
    friend class AccessArbitration;
    explicit NoWriteAccess(AccessArbitration *arbitrator);
    common::p4_id_t p4_id;
  };

  using UniqueAccess = std::unique_lock<std::mutex>;

  WriteAccess write_access(const ::p4::v1::WriteRequest &request,
                           const pi_p4info_t *p4info);
  WriteAccess write_access(common::p4_id_t p4_id);

  NoWriteAccess no_write_access(common::p4_id_t p4_id);

  ReadAccess read_access();

  UniqueAccess unique_access();

 private:
  void release_write_access(const WriteAccess &access);

  void release_no_write_access(const NoWriteAccess &access);

  void release_read_access();

  mutable std::mutex mutex;
  mutable std::condition_variable cv;
  std::set<common::p4_id_t> p4_ids_busy;
  int read_cnt{0};
  int write_cnt{0};
  int no_write_cnt{0};
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_ACCESS_ARBITRATION_H_
