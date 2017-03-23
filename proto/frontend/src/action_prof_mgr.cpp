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

#include <algorithm>
#include <set>
#include <unordered_map>
#include <vector>

#include "google/rpc/code.pb.h"

#include "action_prof_mgr.h"
#include "common.h"

namespace pi {

namespace fe {

namespace proto {

using Id = ActionProfBiMap::Id;
using common::SessionTemp;

void
ActionProfBiMap::add(const Id &id, pi_indirect_handle_t h) {
  bimap.add_mapping_1_2(id, h);
}

const pi_indirect_handle_t *
ActionProfBiMap::retrieve_handle(const Id &id) const {
  return bimap.get_from_1(id);
}

const Id *
ActionProfBiMap::retrieve_id(pi_indirect_handle_t h) const {
  return bimap.get_from_2(h);
}

void
ActionProfBiMap::remove(const Id &id) {
  auto h_ptr = retrieve_handle(id);
  if (h_ptr != nullptr) {
    auto h = *h_ptr;  // need to save the value before modifying the map
    bimap.remove_from_1(id);
    bimap.remove_from_2(h);
  }
}

ActionProfGroupMembership::ActionProfGroupMembership() { }

void
ActionProfGroupMembership::add_member(const Id &member_id) {
  members.insert(member_id);
}

void
ActionProfGroupMembership::remove_member(const Id &member_id) {
  members.erase(member_id);
}

std::vector<Id>
ActionProfGroupMembership::compute_members_to_add(
    const std::vector<Id> &desired_membership) const {
  std::vector<Id> diff;
  std::set_difference(desired_membership.begin(), desired_membership.end(),
                      members.begin(), members.end(),
                      std::inserter(diff, diff.begin()));
  return diff;
}

std::vector<Id>
ActionProfGroupMembership::compute_members_to_remove(
    const std::vector<Id> &desired_membership) const {
  std::vector<Id> diff;
  std::set_difference(members.begin(), members.end(),
                      desired_membership.begin(), desired_membership.end(),
                      std::inserter(diff, diff.begin()));
  return diff;
}

using Status = ActionProfMgr::Status;

ActionProfMgr::ActionProfMgr(pi_dev_tgt_t device_tgt, pi_p4_id_t act_prof_id,
                             pi_p4info_t *p4info)
    : device_tgt(device_tgt), act_prof_id(act_prof_id), p4info(p4info) { }

Status
ActionProfMgr::member_create(const p4::ActionProfileMember &member,
                             const SessionTemp &session) {
  Status status;
  auto action_data = construct_action_data(member.action());
  // TODO(antonin): weight / watch?
  Lock lock(mutex);
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  // we check if the member id already exists
  if (member_bimap.retrieve_handle(member.member_id()) != nullptr) {
    status.set_code(Code::INVALID_ARGUMENT);
    return status;
  }
  pi_indirect_handle_t member_h;
  auto pi_status = ap.member_create(action_data, &member_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    status.set_code(Code::UNKNOWN);
    return status;
  }
  member_bimap.add(member.member_id(), member_h);
  status.set_code(Code::OK);
  return status;
}

Status
ActionProfMgr::group_create(const p4::ActionProfileGroup &group,
                            const SessionTemp &session) {
  Status status;
  Lock lock(mutex);
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  // we check if the group id already exists
  if (group_bimap.retrieve_handle(group.group_id()) != nullptr) {
    status.set_code(Code::INVALID_ARGUMENT);
    return status;
  }
  pi_indirect_handle_t group_h;
  auto pi_status = ap.group_create(group.max_size(), &group_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    status.set_code(Code::UNKNOWN);
    return status;
  }
  group_bimap.add(group.group_id(), group_h);
  group_members.emplace(group.group_id(), ActionProfGroupMembership());
  auto code = group_update_members(ap, group);
  status.set_code(code);
  return status;
}

Status
ActionProfMgr::member_modify(const p4::ActionProfileMember &member,
                             const SessionTemp &session) {
  Status status;
  auto action_data = construct_action_data(member.action());
  // TODO(antonin): weight / watch?
  Lock lock(mutex);
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  auto member_h = member_bimap.retrieve_handle(member.member_id());
  if (member_h == nullptr) {
    status.set_code(Code::INVALID_ARGUMENT);
    return status;
  }
  auto pi_status = ap.member_modify(*member_h, action_data);
  if (pi_status != PI_STATUS_SUCCESS) {
    status.set_code(Code::UNKNOWN);
    return status;
  }
  status.set_code(Code::OK);
  return status;
}

// we stop as soon as there is an error, but make sure to keep consistency
// between device and local state
Status
ActionProfMgr::group_modify(const p4::ActionProfileGroup &group,
                            const SessionTemp &session) {
  Status status;
  Lock lock(mutex);
  auto group_id = group.group_id();
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  auto group_h = group_bimap.retrieve_handle(group_id);
  if (group_h == nullptr) {
    status.set_code(Code::INVALID_ARGUMENT);
    return status;
  }
  auto code = group_update_members(ap, group);
  status.set_code(code);
  return status;
}

Status
ActionProfMgr::member_delete(const p4::ActionProfileMember &member,
                             const SessionTemp &session) {
  Status status;
  Lock lock(mutex);
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  auto member_h = member_bimap.retrieve_handle(member.member_id());
  if (member_h == nullptr) {
    status.set_code(Code::INVALID_ARGUMENT);
    return status;
  }
  auto pi_status = ap.member_delete(*member_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    status.set_code(Code::UNKNOWN);
    return status;
  }
  member_bimap.remove(member.member_id());
  update_group_membership(member.member_id());
  status.set_code(Code::OK);
  return status;
}

Status
ActionProfMgr::group_delete(const p4::ActionProfileGroup &group,
                            const SessionTemp &session) {
  Status status;
  Lock lock(mutex);
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  auto group_h = group_bimap.retrieve_handle(group.group_id());
  if (group_h == nullptr) {
    status.set_code(Code::INVALID_ARGUMENT);
    return status;
  }
  auto pi_status = ap.group_delete(*group_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    status.set_code(Code::UNKNOWN);
    return status;
  }
  group_bimap.remove(group.group_id());
  group_members.erase(group.group_id());
  status.set_code(Code::OK);
  return status;
}

pi::ActionData
ActionProfMgr::construct_action_data(const p4::Action &action) {
  pi::ActionData action_data(p4info, action.action_id());
  for (const auto &p : action.params()) {
    action_data.set_arg(p.param_id(), p.value().data(), p.value().size());
  }
  return action_data;
}

void
ActionProfMgr::update_group_membership(const Id &removed_member_id) {
  for (auto &kv : group_members) kv.second.remove_member(removed_member_id);
}

Code
ActionProfMgr::group_update_members(pi::ActProf &ap,
                                    const p4::ActionProfileGroup &group) {
  Code code;
  std::vector<Id> new_membership(group.members().size());
  std::transform(
      group.members().begin(), group.members().end(), new_membership.begin(),
      [](const p4::ActionProfileGroup::Member &m) { return m.member_id(); });
  std::sort(new_membership.begin(), new_membership.end());
  auto group_id = group.group_id();
  auto &membership = group_members.at(group_id);
  auto members_to_add = membership.compute_members_to_add(new_membership);
  auto members_to_remove = membership.compute_members_to_remove(new_membership);
  // remove members as needed
  code = group_remove_members(
      ap, group_id, members_to_remove.cbegin(), members_to_remove.cend());
  if (code != Code::OK) return code;
  // add members as needed
  code = group_add_members(
      ap, group_id, members_to_add.cbegin(), members_to_add.cend());
  if (code != Code::OK) return code;
  return Code::OK;
}

Code
ActionProfMgr::group_add_member(pi::ActProf &ap, const Id &group_id,
                                const Id &member_id) {
  auto &membership = group_members.at(group_id);
  auto group_h = group_bimap.retrieve_handle(group_id);
  assert(group_h);
  auto member_h = member_bimap.retrieve_handle(member_id);
  if (member_h == nullptr) {  // the member does not exist
    return Code::INVALID_ARGUMENT;
  }
  auto pi_status = ap.group_add_member(*group_h, *member_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    return Code::UNKNOWN;
  }
  membership.add_member(member_id);
  return Code::OK;
}

Code
ActionProfMgr::group_remove_member(pi::ActProf &ap, const Id &group_id,
                                   const Id &member_id) {
  auto &membership = group_members.at(group_id);
  auto group_h = group_bimap.retrieve_handle(group_id);
  assert(group_h);
  auto member_h = member_bimap.retrieve_handle(member_id);
  if (member_h == nullptr) {  // the member does not exist
    return Code::INVALID_ARGUMENT;
  }
  auto pi_status = ap.group_remove_member(*group_h, *member_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    return Code::UNKNOWN;
  }
  membership.remove_member(member_id);
  return Code::OK;
}

const pi_indirect_handle_t *
ActionProfMgr::retrieve_member_handle(const Id &member_id) {
  Lock lock(mutex);
  return member_bimap.retrieve_handle(member_id);
}

const pi_indirect_handle_t *
ActionProfMgr::retrieve_group_handle(const Id &group_id) {
  Lock lock(mutex);
  return group_bimap.retrieve_handle(group_id);
}

const Id *
ActionProfMgr::retrieve_member_id(pi_indirect_handle_t h) {
  Lock lock(mutex);
  return member_bimap.retrieve_id(h);
}

const Id *
ActionProfMgr::retrieve_group_id(pi_indirect_handle_t h) {
  Lock lock(mutex);
  return group_bimap.retrieve_id(h);
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
