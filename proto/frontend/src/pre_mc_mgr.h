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

#ifndef SRC_PRE_MC_MGR_H_
#define SRC_PRE_MC_MGR_H_

#include <PI/pi_base.h>
#include <PI/pi_mc.h>

#include <mutex>
#include <set>
#include <unordered_map>

#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

namespace pi {

namespace fe {

namespace proto {

struct McSessionTemp;

// This class is used to map P4Runtime MulticastGroupEntry messages to
// lower-level PI operations. It currently does not do any rollback in case of
// error, which means a single P4Runtime multicast group modification can be
// only partially committed to the target in case of error.
class PreMcMgr {
 public:
  using Status = ::google::rpc::Status;
  using GroupEntry = ::p4::v1::MulticastGroupEntry;
  using GroupId = uint32_t;
  using RId = uint32_t;

  enum class GroupOwner {
    CLIENT,
    CLONE_MGR,
  };

  explicit PreMcMgr(pi_dev_id_t device_id)
      : device_id(device_id) { }

  Status group_create(const GroupEntry &group_entry,
                      GroupOwner = GroupOwner::CLIENT);
  Status group_modify(const GroupEntry &group_entry);
  Status group_delete(const GroupEntry &group_entry);

  // user-defined multicast group ids must be in the range
  // [0,first_reserved_group[; ideally this should be configurable based on the
  // target.
  static constexpr GroupId first_reserved_group_id() { return 1 << 15; }

 private:
  using Mutex = std::mutex;
  using Lock = std::lock_guard<Mutex>;

  struct Node {
    pi_mc_node_handle_t node_h;
    std::set<pi_mc_port_t> eg_ports{};
  };

  struct Group {
    pi_mc_grp_handle_t group_h;
    std::unordered_map<RId, Node> nodes{};
    GroupOwner owner;
  };

  static Status make_new_group(const GroupEntry &group_entry, Group *group);

  Status create_and_attach_node(const McSessionTemp &session,
                                pi_mc_grp_handle_t group_h,
                                RId rid,
                                Node *node);
  Status modify_node(const McSessionTemp &session, const Node &node);
  Status detach_and_delete_node(const McSessionTemp &session,
                                pi_mc_grp_handle_t group_h,
                                const Node &node);

  pi_dev_id_t device_id;
  std::unordered_map<GroupId, Group> groups{};
  mutable Mutex mutex{};
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_PRE_MC_MGR_H_
