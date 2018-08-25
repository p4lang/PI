/* Copyright 2018-present Barefoot Networks, Inc.
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

#ifndef SRC_PRE_CLONE_MGR_H_
#define SRC_PRE_CLONE_MGR_H_

#include <PI/pi_base.h>
#include <PI/pi_clone.h>

#include <bitset>
#include <mutex>
#include <unordered_map>

#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "pre_mc_mgr.h"

namespace pi {

namespace fe {

namespace proto {

namespace common { struct SessionTemp; }  // namespace common

// This class is used to map P4Runtime CloneSessionEntry messages to lower-level
// PI operations. At the moment every clone session is associated to a multicast
// group.
class PreCloneMgr {
 public:
  using Status = ::google::rpc::Status;
  using CloneSession = ::p4::v1::CloneSessionEntry;
  using CloneSessionId = uint32_t;
  using SessionTemp = common::SessionTemp;

  PreCloneMgr(pi_dev_tgt_t device_tgt, PreMcMgr* mc_mgr);

  Status session_create(const CloneSession &clone_session,
                        const SessionTemp &session);
  Status session_modify(const CloneSession &clone_session,
                        const SessionTemp &session);
  Status session_delete(const CloneSession &clone_session,
                        const SessionTemp &session);

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  // TODO(antonin): this should ideally be configurable based on te target but
  // these seem like a reasonnable place to start with.
  static constexpr CloneSessionId kMinCloneSessionId = 1;
  static constexpr CloneSessionId kMaxCloneSessionId = 512;

  Status session_set(const CloneSession &clone_session,
                     PreMcMgr::GroupId mc_group_id,
                     const SessionTemp &session);

  static Status validate_session_id(CloneSessionId session_id);

  pi_dev_tgt_t device_tgt;
  PreMcMgr* mc_mgr;  // non-owning pointer
  // which sessions exist
  std::bitset<kMaxCloneSessionId> sessions{};
  mutable Mutex mutex{};
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_PRE_CLONE_MGR_H_
