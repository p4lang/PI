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

#include <PI/pi_mc.h>

#include <vector>

#include "google/rpc/code.pb.h"

#include "common.h"
#include "pre_mc_mgr.h"
#include "report_error.h"

namespace p4v1 = ::p4::v1;

namespace pi {

namespace fe {

namespace proto {

using Code = ::google::rpc::Code;
using Status = PreMcMgr::Status;
using GroupEntry = PreMcMgr::GroupEntry;

struct McLocalCleanupIface {
  virtual ~McLocalCleanupIface() { }

  virtual Status cleanup(const McSessionTemp &session) = 0;
  virtual void cancel() = 0;
};

class McSessionTemp final
    : public common::SessionCleanup<McSessionTemp, McLocalCleanupIface> {
 public:
  McSessionTemp() {
    pi_mc_session_init(&sess);
  }

  ~McSessionTemp() {
    pi_mc_session_cleanup(sess);
  }

  pi_mc_session_handle_t get() const { return sess; }

 private:
  pi_mc_session_handle_t sess;
};

struct PreMcMgr::GroupCleanupTask : public McLocalCleanupIface {
  GroupCleanupTask(PreMcMgr *pre_mgr, pi_mc_grp_handle_t group_h)
      : pre_mgr(pre_mgr), group_h(group_h) { }

  Status cleanup(const McSessionTemp &session) override {
    if (!pre_mgr) RETURN_OK_STATUS();
    auto pi_status = pi_mc_grp_delete(
        session.get(), pre_mgr->device_id, group_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error encountered when cleaning up multicast group. "
          "This is a serious error and there may be a dangling group. "
          "You may need to reboot the system");
    }
    RETURN_OK_STATUS();
  }

  void cancel() override {
    pre_mgr = nullptr;
  }

  PreMcMgr *pre_mgr;
  pi_mc_grp_handle_t group_h;
};

struct PreMcMgr::NodeDetachCleanupTask : public McLocalCleanupIface {
  NodeDetachCleanupTask(PreMcMgr *pre_mgr,
                        pi_mc_grp_handle_t group_h,
                        pi_mc_node_handle_t node_h)
      : pre_mgr(pre_mgr), group_h(group_h), node_h(node_h) { }

  Status cleanup(const McSessionTemp &session) override {
    if (!pre_mgr) RETURN_OK_STATUS();
    auto pi_status = pi_mc_grp_detach_node(
        session.get(), pre_mgr->device_id, group_h, node_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error encountered when detaching multicast node from group. "
          "This is a serious error that should definitely not happen. "
          "You may need to reboot the system");
    }
    RETURN_OK_STATUS();
  }

  void cancel() override {
    pre_mgr = nullptr;
  }

  PreMcMgr *pre_mgr;
  pi_mc_grp_handle_t group_h;
  pi_mc_node_handle_t node_h;
};

struct PreMcMgr::NodeCleanupTask : public McLocalCleanupIface {
  NodeCleanupTask(PreMcMgr *pre_mgr, pi_mc_node_handle_t node_h)
      : pre_mgr(pre_mgr), node_h(node_h) { }

  Status cleanup(const McSessionTemp &session) override {
    if (!pre_mgr) RETURN_OK_STATUS();
    auto pi_status = pi_mc_node_delete(
        session.get(), pre_mgr->device_id, node_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error encountered when deleting multicast node from group. "
          "This is a serious error and there may be a dangling node. "
          "You may need to reboot the system");
    }
    RETURN_OK_STATUS();
  }

  void cancel() override {
    pre_mgr = nullptr;
  }

  PreMcMgr *pre_mgr;
  pi_mc_node_handle_t node_h;
};

/* static */ Status
PreMcMgr::make_new_group(const GroupEntry &group_entry, Group *group) {
  for (const auto &replica : group_entry.replicas()) {
    auto rid = static_cast<RId>(replica.instance());
    auto eg_port = static_cast<pi_mc_port_t>(replica.egress_port());
    auto &node = group->nodes[rid];
    auto p = node.eg_ports.insert(eg_port);
    if (!p.second) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Duplicate replica in multicast group");
    }
  }
  RETURN_OK_STATUS();
}

Status
PreMcMgr::create_and_attach_node(McSessionTemp *session,
                                 pi_mc_grp_handle_t group_h,
                                 RId rid,
                                 Node *node) {
  pi_status_t pi_status;
  std::vector<pi_mc_port_t> eg_ports_seq(
      node->eg_ports.begin(), node->eg_ports.end());
  pi_status = pi_mc_node_create(
      session->get(), device_id, rid,
      eg_ports_seq.size(), eg_ports_seq.data(), &node->node_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  session->cleanup_task_push(std::unique_ptr<NodeCleanupTask>(
      new NodeCleanupTask(this, node->node_h)));
  pi_status = pi_mc_grp_attach_node(
      session->get(), device_id, group_h, node->node_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  session->cleanup_task_push(std::unique_ptr<NodeDetachCleanupTask>(
      new NodeDetachCleanupTask(this, group_h, node->node_h)));
  RETURN_OK_STATUS();
}

Status
PreMcMgr::modify_node(const McSessionTemp &session, const Node &node) {
  pi_status_t pi_status;
  std::vector<pi_mc_port_t> eg_ports_seq(
      node.eg_ports.begin(), node.eg_ports.end());
  pi_status = pi_mc_node_modify(session.get(), device_id, node.node_h,
                                eg_ports_seq.size(), eg_ports_seq.data());
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  RETURN_OK_STATUS();
}

Status
PreMcMgr::detach_and_delete_node(const McSessionTemp &session,
                                 pi_mc_grp_handle_t group_h,
                                 const Node &node) {
  pi_status_t pi_status;
  pi_status = pi_mc_grp_detach_node(
      session.get(), device_id, group_h, node.node_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  pi_status = pi_mc_node_delete(session.get(), device_id, node.node_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when modifying multicast group in target");
  }
  RETURN_OK_STATUS();
}

namespace {

template <typename Fn, typename ...Args>
Status execute_operation(const Fn &fn, PreMcMgr *mgr, Args &&...args) {
  McSessionTemp session;
  auto status = (mgr->*fn)(&session, std::forward<Args>(args)...);
  auto cleanup_status = session.local_cleanup();
  return IS_OK(cleanup_status) ? status : cleanup_status;
}

}  // namespace

Status
PreMcMgr::group_create_(McSessionTemp *session,
                        GroupId group_id,
                        Group *group) {
  session->cleanup_scope_push();
  auto pi_status = pi_mc_grp_create(
      session->get(), device_id, group_id, &group->group_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(Code::UNKNOWN,
                        "Error when creating multicast group in target");
  }
  session->cleanup_task_push(std::unique_ptr<GroupCleanupTask>(
      new GroupCleanupTask(this, group->group_h)));
  for (auto &node_p : group->nodes) {
    RETURN_IF_ERROR(create_and_attach_node(
        session, group->group_h, node_p.first, &node_p.second));
  }
  session->cleanup_scope_pop();
  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_create(const GroupEntry &group_entry, GroupOwner owner) {
  auto group_id = static_cast<GroupId>(group_entry.multicast_group_id());
  Lock lock(mutex);
  if (groups.find(group_id) != groups.end())
    RETURN_ERROR_STATUS(Code::ALREADY_EXISTS, "Multicast group already exists");

  Group group;
  group.owner = owner;
  RETURN_IF_ERROR(make_new_group(group_entry, &group));

  RETURN_IF_ERROR(execute_operation(
      &PreMcMgr::group_create_, this, group_id, &group));

  groups.emplace(group_id, std::move(group));
  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_modify_(McSessionTemp *session,
                        GroupId group_id,
                        Group *old_group,
                        Group *new_group) {
  (void) group_id;
  session->cleanup_scope_push();
  for (auto &node_p : new_group->nodes) {
    auto rid = node_p.first;
    auto old_node_it = old_group->nodes.find(rid);
    if (old_node_it == old_group->nodes.end()) {
      RETURN_IF_ERROR(create_and_attach_node(
          session, new_group->group_h, node_p.first, &node_p.second));
    } else {
      node_p.second.node_h = old_node_it->second.node_h;
      if (node_p.second.eg_ports != old_node_it->second.eg_ports)
        RETURN_IF_ERROR(modify_node(*session, node_p.second));
      old_group->nodes.erase(old_node_it);
    }
  }
  // if a call to create_and_attach_node fails, we cleanup all the nodes we have
  // created
  session->cleanup_scope_pop();
  for (auto &node_p : old_group->nodes) {
    RETURN_IF_ERROR(detach_and_delete_node(
        *session, new_group->group_h, node_p.second));
  }
  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_modify(const GroupEntry &group_entry) {
  auto group_id = static_cast<GroupId>(group_entry.multicast_group_id());
  Lock lock(mutex);
  auto group_it = groups.find(group_id);
  if (group_it == groups.end())
    RETURN_ERROR_STATUS(Code::NOT_FOUND, "Multicast group does not exist");
  auto &old_group = group_it->second;

  Group new_group;
  new_group.group_h = old_group.group_h;
  new_group.owner = old_group.owner;
  RETURN_IF_ERROR(make_new_group(group_entry, &new_group));

  // if one node fails to be created / attached, we cleanup all the created
  // nodes, and keep the old group definition
  // detach_and_delete_node is unlikely to fail so we don't accomodate for that
  // case for now
  RETURN_IF_ERROR(execute_operation(
      &PreMcMgr::group_modify_, this, group_id, &old_group, &new_group));

  group_it->second = std::move(new_group);
  RETURN_OK_STATUS();
}

Status
PreMcMgr::group_delete(const GroupEntry &group_entry) {
  auto group_id = static_cast<GroupId>(group_entry.multicast_group_id());
  Lock lock(mutex);
  auto group_it = groups.find(group_id);
  if (group_it == groups.end())
    RETURN_ERROR_STATUS(Code::NOT_FOUND, "Multicast group does not exist");
  auto& group = group_it->second;

  McSessionTemp session;

  for (auto& node_p : group.nodes) {
    RETURN_IF_ERROR(detach_and_delete_node(
        session, group.group_h, node_p.second));
  }

  auto pi_status = pi_mc_grp_delete(session.get(), device_id, group.group_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when deleting multicast group in target");
  }

  groups.erase(group_id);
  RETURN_OK_STATUS();
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
