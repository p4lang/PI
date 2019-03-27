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

#include <PI/proto/util.h>

#include <algorithm>
#include <set>
#include <unordered_map>
#include <vector>

#include "google/rpc/code.pb.h"

#include "action_helpers.h"
#include "action_prof_mgr.h"
#include "common.h"
#include "logger.h"
#include "report_error.h"
#include "statusor.h"

namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;

namespace pi {

namespace fe {

namespace proto {

using Id = ActionProfBiMap::Id;
using common::SessionTemp;
using common::make_invalid_p4_id_status;
using Code = ::google::rpc::Code;

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

bool
ActionProfBiMap::empty() const {
  return bimap.empty();
}

ActionProfGroupMembership::ActionProfGroupMembership(size_t max_size_user)
    : max_size_user(max_size_user) { }

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

size_t
ActionProfGroupMembership::get_max_size_user() const {
  return max_size_user;
}

using Status = ActionProfMgr::Status;

ActionProfMgr::ActionProfMgr(pi_dev_tgt_t device_tgt, pi_p4_id_t act_prof_id,
                             pi_p4info_t *p4info, PiApiChoice pi_api_choice)
    : device_tgt(device_tgt), act_prof_id(act_prof_id), p4info(p4info),
      pi_api_choice(pi_api_choice) {
  max_group_size = pi_p4info_act_prof_max_grp_size(p4info, act_prof_id);
}

Status
ActionProfMgr::member_create(const p4v1::ActionProfileMember &member,
                             const SessionTemp &session) {
  RETURN_IF_ERROR(validate_action(member.action()));
  auto action_data = construct_action_data(member.action());
  Lock lock(mutex);
  RETURN_IF_ERROR(check_selector_usage(SelectorUsage::MANUAL));
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  // we check if the member id already exists
  if (member_bimap.retrieve_handle(member.member_id()) != nullptr) {
    RETURN_ERROR_STATUS(
        Code::ALREADY_EXISTS, "Duplicate member id: {}", member.member_id());
  }
  pi_indirect_handle_t member_h;
  auto pi_status = ap.member_create(action_data, &member_h);
  if (pi_status != PI_STATUS_SUCCESS)
    RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when creating member on target");
  member_bimap.add(member.member_id(), member_h);
  selector_usage = SelectorUsage::MANUAL;
  RETURN_OK_STATUS();
}

StatusOr<size_t>
ActionProfMgr::validate_max_group_size(int max_size) {
/*
 - If max_group_size is greater than 0, then max_size must be greater than 0,
   and less than or equal to max_group_size. We assume that the target can
   support selector groups for which the sum of all member weights is up to
   max_group_size, or the P4Runtime server would have rejected the Forwarding
   Pipeline Config. If max_size is greater than max_group_size, the server must
   return INVALID_ARGUMENT.

 - Otherwise (i.e. if max_group_size is 0), the P4Runtime client can set
   max_size to any value greater than or equal to 0.

   - A max_size of 0 indicates that the client is not able to specify a maximum
     size at group-creation time, and the target should use the maximum value it
     can support. If the maximum value supported by the target is exceeded
     during a write update (INSERT or MODIFY), the target must return a
     RESOURCE_EXHAUSTED error.

   - If max_size is greater than 0 and the value is not supported by the target,
     the server must return a RESOURCE_EXHAUSTED error at group-creation time.
*/
  if (max_size < 0) {
    RETURN_ERROR_STATUS(
        Code::INVALID_ARGUMENT, "Group max_size cannot be less than 0");
  }
  auto max_size_ = static_cast<size_t>(max_size);
  if (max_group_size > 0 && max_size_ > max_group_size) {
    RETURN_ERROR_STATUS(
        Code::INVALID_ARGUMENT,
        "Group max_size cannot exceed static max_group_size (from P4Info)");
  }
  return max_size_;
}

Status
ActionProfMgr::group_create(const p4v1::ActionProfileGroup &group,
                            const SessionTemp &session) {
  auto max_size = validate_max_group_size(group.max_size());
  RETURN_IF_ERROR(max_size.status());
  Lock lock(mutex);
  RETURN_IF_ERROR(check_selector_usage(SelectorUsage::MANUAL));
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  // we check if the group id already exists
  if (group_bimap.retrieve_handle(group.group_id()) != nullptr) {
    RETURN_ERROR_STATUS(
        Code::ALREADY_EXISTS, "Duplicate group id: {}", group.group_id());
  }
  pi_indirect_handle_t group_h;
  auto pi_status = ap.group_create(max_size.ValueOrDie(), &group_h);
  if (pi_status != PI_STATUS_SUCCESS)
    RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when creating group on target");
  group_bimap.add(group.group_id(), group_h);
  group_members.emplace(group.group_id(),
                        ActionProfGroupMembership(group.max_size()));
  selector_usage = SelectorUsage::MANUAL;
  return group_update_members(ap, group);
}

Status
ActionProfMgr::member_modify(const p4v1::ActionProfileMember &member,
                             const SessionTemp &session) {
  RETURN_IF_ERROR(validate_action(member.action()));
  auto action_data = construct_action_data(member.action());
  Lock lock(mutex);
  RETURN_IF_ERROR(check_selector_usage(SelectorUsage::MANUAL));
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  auto member_h = member_bimap.retrieve_handle(member.member_id());
  if (member_h == nullptr) {
    RETURN_ERROR_STATUS(Code::NOT_FOUND,
                        "Member id does not exist: {}", member.member_id());
  }
  auto pi_status = ap.member_modify(*member_h, action_data);
  if (pi_status != PI_STATUS_SUCCESS)
    RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when modifying member on target");
  RETURN_OK_STATUS();
}

// we stop as soon as there is an error, but make sure to keep consistency
// between device and local state
Status
ActionProfMgr::group_modify(const p4v1::ActionProfileGroup &group,
                            const SessionTemp &session) {
  Lock lock(mutex);
  RETURN_IF_ERROR(check_selector_usage(SelectorUsage::MANUAL));
  auto group_id = group.group_id();
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  auto group_h = group_bimap.retrieve_handle(group_id);
  if (group_h == nullptr) {
    RETURN_ERROR_STATUS(Code::NOT_FOUND,
                        "Group id does not exist: {}", group.group_id());
  }
  auto max_size_user = group_members.at(group_id).get_max_size_user();
  // TODO(antonin): I don't want to take the risk to break existing
  // implementations (for not much benefit) so no check is performed if max_size
  // is "unset".
  if (group.max_size() != 0 &&
      static_cast<size_t>(group.max_size()) != max_size_user) {
    RETURN_ERROR_STATUS(
        Code::INVALID_ARGUMENT,
        "Cannot change group max_size after group creation");
  }
  return group_update_members(ap, group);
}

Status
ActionProfMgr::member_delete(const p4v1::ActionProfileMember &member,
                             const SessionTemp &session) {
  Lock lock(mutex);
  RETURN_IF_ERROR(check_selector_usage(SelectorUsage::MANUAL));
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  auto member_h = member_bimap.retrieve_handle(member.member_id());
  if (member_h == nullptr) {
    RETURN_ERROR_STATUS(Code::NOT_FOUND,
                        "Member id does not exist: {}", member.member_id());
  }
  auto pi_status = ap.member_delete(*member_h);
  if (pi_status != PI_STATUS_SUCCESS)
    RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when deleting member on target");
  member_bimap.remove(member.member_id());
  update_group_membership(member.member_id());
  reset_selector_usage();
  RETURN_OK_STATUS();
}

Status
ActionProfMgr::group_delete(const p4v1::ActionProfileGroup &group,
                            const SessionTemp &session) {
  Lock lock(mutex);
  RETURN_IF_ERROR(check_selector_usage(SelectorUsage::MANUAL));
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  auto group_h = group_bimap.retrieve_handle(group.group_id());
  if (group_h == nullptr) {
    RETURN_ERROR_STATUS(Code::NOT_FOUND,
                        "Group id does not exist: {}", group.group_id());
  }
  auto pi_status = ap.group_delete(*group_h);
  if (pi_status != PI_STATUS_SUCCESS)
    RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when deleting group on target");
  group_bimap.remove(group.group_id());
  if (pi_api_choice == PiApiChoice::INDIVIDUAL_ADDS_AND_REMOVES)
    group_members.erase(group.group_id());
  reset_selector_usage();
  RETURN_OK_STATUS();
}

bool
ActionProfMgr::group_get_max_size_user(const Id &group_id,
                                       size_t *max_size_user) const {
  auto it = group_members.find(group_id);
  if (it == group_members.end()) return false;
  *max_size_user = it->second.get_max_size_user();
  return true;
}

namespace {

struct OneShotGroupCleanupTask : common::LocalCleanupIface {
  OneShotGroupCleanupTask(pi::ActProf *ap, pi_indirect_handle_t group_h)
      : ap(ap), group_h(group_h) { }

  Status cleanup(const SessionTemp &session) override {
    (void)session;
    if (!ap) RETURN_OK_STATUS();
    auto pi_status = ap->group_delete(group_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error encountered when cleaning up action profile group created "
          "by one-shot indirect table programming. This is a serious error and "
          "there is now a dangling action profile group. You may need to "
          "reboot the system");
    }
    RETURN_OK_STATUS();
  }

  void cancel() override {
    ap = nullptr;
  }

  pi::ActProf *ap;
  pi_indirect_handle_t group_h;
};

struct OneShotMemberCleanupTask : common::LocalCleanupIface {
  OneShotMemberCleanupTask(pi::ActProf *ap, pi_indirect_handle_t member_h)
      : ap(ap), member_h(member_h) { }

  Status cleanup(const SessionTemp &session) override {
    (void)session;
    if (!ap) RETURN_OK_STATUS();
    auto pi_status = ap->member_delete(member_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::INTERNAL,
          "Error encountered when cleaning up action profile member created "
          "by one-shot indirect table programming. This is a serious error and "
          "you may need to reboot the system");
    }
    RETURN_OK_STATUS();
  }

  void cancel() override {
    ap = nullptr;
  }

  pi::ActProf *ap;
  pi_indirect_handle_t member_h;
};

}  // namespace

Status
ActionProfMgr::oneshot_group_create(
    const p4::v1::ActionProfileActionSet &action_set,
    pi_indirect_handle_t *group_h,
    SessionTemp *session) {
  if (action_set.action_profile_actions().empty()) {
    RETURN_ERROR_STATUS(
        Code::UNIMPLEMENTED, "No support for empty action profile groups");
  }
  for (const auto &action : action_set.action_profile_actions())
    RETURN_IF_ERROR(validate_action(action.action()));

  size_t sum_of_weights = 0;
  for (const auto &action : action_set.action_profile_actions()) {
    if (action.weight() <= 0) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Member weight must be a positive integer value");
    }
    // TODO(antonin): support arbitrary weight
    if (action.weight() != 1) {
      RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
                          "Only weight values of 1 are currently supported");
    }
    // TODO(antonin): support watch
    if (action.watch() != 0) {
      // do not reject the request outright in case it breaks an existing
      // controller.
      Logger::get()->warn("Watch attribute for members not implemented yet");
    }
    sum_of_weights += action.weight();
  }

  if (max_group_size > 0 && sum_of_weights > max_group_size) {
    RETURN_ERROR_STATUS(
        Code::RESOURCE_EXHAUSTED,
        "Sum of weights exceeds static max_group_size (from P4Info)");
  }

  Lock lock(mutex);
  RETURN_IF_ERROR(check_selector_usage(SelectorUsage::ONESHOT));
  session->cleanup_scope_push();
  pi::ActProf ap(session->get(), device_tgt, p4info, act_prof_id);
  std::vector<pi_indirect_handle_t> members;
  for (const auto &action : action_set.action_profile_actions()) {
    pi_indirect_handle_t member_h;
    auto action_data = construct_action_data(action.action());
    auto pi_status = ap.member_create(action_data, &member_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::UNKNOWN, "Error when creating member on target");
    }
    members.push_back(member_h);
    session->cleanup_task_push(std::unique_ptr<OneShotMemberCleanupTask>(
        new OneShotMemberCleanupTask(&ap, member_h)));
  }
  {
    auto pi_status = ap.group_create(
        action_set.action_profile_actions_size(), group_h);
    if (pi_status != PI_STATUS_SUCCESS)
      RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when creating group on target");
    session->cleanup_task_push(std::unique_ptr<OneShotGroupCleanupTask>(
        new OneShotGroupCleanupTask(&ap, *group_h)));
  }
  if (pi_api_choice == PiApiChoice::INDIVIDUAL_ADDS_AND_REMOVES) {
    for (const auto &member_h : members) {
      auto pi_status = ap.group_add_member(*group_h, member_h);
      if (pi_status != PI_STATUS_SUCCESS) {
        RETURN_ERROR_STATUS(
            Code::UNKNOWN, "Error when adding member to group on target");
      }
    }
  } else if (pi_api_choice == PiApiChoice::SET_MEMBERSHIP) {
    auto pi_status = ap.group_set_members(
        *group_h, members.size(), members.data());
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::UNKNOWN, "Error when setting group membership on target");
    }
  } else {
    RETURN_ERROR_STATUS(Code::INTERNAL, "Unknown PiApiChoice");
  }
  session->cleanup_scope_pop();
  auto p = oneshot_group_members.emplace(*group_h, members);
  assert(p.second);
  (void)p;
  selector_usage = SelectorUsage::ONESHOT;
  RETURN_OK_STATUS();
}

Status
ActionProfMgr::oneshot_group_delete(pi_indirect_handle_t group_h,
                                    const SessionTemp &session) {
  Lock lock(mutex);
  RETURN_IF_ERROR(check_selector_usage(SelectorUsage::ONESHOT));
  auto members_it = oneshot_group_members.find(group_h);
  assert(members_it != oneshot_group_members.end());
  pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);
  for (const auto &member_h : members_it->second) {
    auto pi_status = ap.member_delete(member_h);
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::UNKNOWN, "Error when deleting member on target");
    }
  }
  {
    auto pi_status = ap.group_delete(group_h);
    if (pi_status != PI_STATUS_SUCCESS)
      RETURN_ERROR_STATUS(Code::UNKNOWN, "Error when deleting group on target");
  }
  oneshot_group_members.erase(members_it);
  reset_selector_usage();
  RETURN_OK_STATUS();
}

bool
ActionProfMgr::oneshot_group_get_members(
    pi_indirect_handle_t group_h,
    std::vector<pi_indirect_handle_t> *members_h) const {
  Lock lock(mutex);
  auto it = oneshot_group_members.find(group_h);
  if (it == oneshot_group_members.end()) return false;
  *members_h = it->second;
  return true;
}

ActionProfMgr::SelectorUsage
ActionProfMgr::get_selector_usage() const {
  Lock lock(mutex);
  return selector_usage;
}

bool
ActionProfMgr::check_p4_action_id(pi_p4_id_t p4_id) const {
  using pi::proto::util::resource_type_from_id;
  return (resource_type_from_id(p4_id) == p4configv1::P4Ids::ACTION)
      && pi_p4info_is_valid_id(p4info, p4_id);
}

pi::ActionData
ActionProfMgr::construct_action_data(const p4v1::Action &action) {
  pi::ActionData action_data(p4info, action.action_id());
  for (const auto &p : action.params()) {
    action_data.set_arg(p.param_id(), p.value().data(), p.value().size());
  }
  return action_data;
}

Status
ActionProfMgr::validate_action(const p4v1::Action &action) {
  auto action_id = action.action_id();
  if (!check_p4_action_id(action_id))
    return make_invalid_p4_id_status();
  if (!pi_p4info_act_prof_is_action_of(p4info, act_prof_id, action_id)) {
    RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                        "Invalid action for action profile");
  }
  return validate_action_data(p4info, action);
}

Status
ActionProfMgr::check_selector_usage(SelectorUsage attempted_usage) const {
  if (selector_usage == SelectorUsage::UNSPECIFIED ||
      selector_usage == attempted_usage)
    RETURN_OK_STATUS();
  RETURN_ERROR_STATUS(
      Code::INVALID_ARGUMENT,
      "Invalid attempt to mix action selector programming modes");
}

void
ActionProfMgr::reset_selector_usage() {
  if (member_bimap.empty() &&
      group_bimap.empty() &&
      oneshot_group_members.empty())
    selector_usage = SelectorUsage::UNSPECIFIED;
}

void
ActionProfMgr::update_group_membership(const Id &removed_member_id) {
  if (pi_api_choice == PiApiChoice::INDIVIDUAL_ADDS_AND_REMOVES)
    for (auto &kv : group_members) kv.second.remove_member(removed_member_id);
}

Status
ActionProfMgr::group_update_members(pi::ActProf &ap,
                                    const p4v1::ActionProfileGroup &group) {
  size_t sum_of_weights = 0;
  for (const auto& member : group.members()) {
    if (member.weight() <= 0) {
      RETURN_ERROR_STATUS(Code::INVALID_ARGUMENT,
                          "Member weight must be a positive integer value");
    }
    // TODO(antonin): support arbitrary weight
    if (member.weight() != 1) {
      RETURN_ERROR_STATUS(Code::UNIMPLEMENTED,
                          "Only weight values of 1 are currently supported");
    }
    // TODO(antonin): support watch
    if (member.watch() != 0) {
      // do not reject the request outright in case it breaks an existing
      // controller.
      Logger::get()->warn("Watch attribute for members not implemented yet");
    }
    sum_of_weights += member.weight();
  }

  auto group_id = group.group_id();
  auto &membership = group_members.at(group_id);

  auto max_size_user = membership.get_max_size_user();
  auto max_size = (max_size_user == 0) ? max_group_size : max_size_user;
  if (max_size > 0 && sum_of_weights > max_size) {
    RETURN_ERROR_STATUS(Code::RESOURCE_EXHAUSTED,
                        "Sum of member weights exceeds maximum group size");
  }

  std::vector<Id> new_membership(group.members().size());
  std::transform(
      group.members().begin(), group.members().end(), new_membership.begin(),
      [](const p4v1::ActionProfileGroup::Member &m) { return m.member_id(); });
  std::sort(new_membership.begin(), new_membership.end());

  // TODO(antonin): uncomment when weights are supported
  // // check for duplicates (new_membership is sorted)
  // if (new_membership.size() > 0) {
  //   auto prev_it = new_membership.begin();
  //   for (auto it = new_membership.begin() + 1;
  //        it != new_membership.end();
  //        it++) {
  //     if (*it == *prev_it) {
  //       RETURN_ERROR_STATUS(
  //           Code::INVALID_ARGUMENT,
  //           "Duplicate member id {} for group {}, use weights instead",
  //           *it, group_id);
  //       break;
  //     }
  //     prev_it = it;
  //   }
  // }

  if (pi_api_choice == PiApiChoice::INDIVIDUAL_ADDS_AND_REMOVES) {
    // TODO(antonin): make this code smarter so that the group is never empty
    // and never too big at any given time.
    auto members_to_add = membership.compute_members_to_add(new_membership);
    auto members_to_remove = membership.compute_members_to_remove(
        new_membership);
    // remove members as needed
    RETURN_IF_ERROR(group_remove_members(
        ap, group_id, members_to_remove.cbegin(), members_to_remove.cend()));
    // add members as needed
    RETURN_IF_ERROR(group_add_members(
        ap, group_id, members_to_add.cbegin(), members_to_add.cend()));
    RETURN_OK_STATUS();
  } else if (pi_api_choice == PiApiChoice::SET_MEMBERSHIP) {
    auto group_h = group_bimap.retrieve_handle(group_id);
    assert(group_h);  // we already confirmed that the group existed
    std::vector<pi_indirect_handle_t> members_h;
    for (auto member : group.members()) {
      auto member_id = member.member_id();
      auto member_h = member_bimap.retrieve_handle(member_id);
      if (member_h == nullptr) {  // the member does not exist
        RETURN_ERROR_STATUS(
            Code::NOT_FOUND, "Member id does not exist: {}", member_id);
      }
      members_h.push_back(*member_h);
    }
    auto pi_status = ap.group_set_members(
        *group_h, members_h.size(), members_h.data());
    if (pi_status != PI_STATUS_SUCCESS) {
      RETURN_ERROR_STATUS(
          Code::UNKNOWN, "Error when setting group membership on target");
    }
    RETURN_OK_STATUS();
  }
  RETURN_ERROR_STATUS(Code::INTERNAL, "Unknown PiApiChoice");
}

Status
ActionProfMgr::group_add_member(pi::ActProf &ap, const Id &group_id,
                                const Id &member_id) {
  auto &membership = group_members.at(group_id);
  auto group_h = group_bimap.retrieve_handle(group_id);
  assert(group_h);
  auto member_h = member_bimap.retrieve_handle(member_id);
  if (member_h == nullptr) {  // the member does not exist
    RETURN_ERROR_STATUS(
        Code::NOT_FOUND, "Member id does not exist: {}", member_id);
  }
  auto pi_status = ap.group_add_member(*group_h, *member_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when adding member to group on target");
  }
  membership.add_member(member_id);
  RETURN_OK_STATUS();
}

Status
ActionProfMgr::group_remove_member(pi::ActProf &ap, const Id &group_id,
                                   const Id &member_id) {
  auto &membership = group_members.at(group_id);
  auto group_h = group_bimap.retrieve_handle(group_id);
  assert(group_h);
  auto member_h = member_bimap.retrieve_handle(member_id);
  if (member_h == nullptr) {  // the member does not exist
    RETURN_ERROR_STATUS(
        Code::NOT_FOUND, "Member id does not exist: {}", member_id);
  }
  auto pi_status = ap.group_remove_member(*group_h, *member_h);
  if (pi_status != PI_STATUS_SUCCESS) {
    RETURN_ERROR_STATUS(
        Code::UNKNOWN, "Error when removing member from group on target");
  }
  membership.remove_member(member_id);
  RETURN_OK_STATUS();
}

bool
ActionProfMgr::retrieve_member_handle(const Id &member_id,
                                      pi_indirect_handle_t *member_h) const {
  Lock lock(mutex);
  auto *h_ptr = member_bimap.retrieve_handle(member_id);
  if (!h_ptr) return false;
  *member_h = *h_ptr;
  return true;
}

bool
ActionProfMgr::retrieve_group_handle(const Id &group_id,
                                     pi_indirect_handle_t *group_h) const {
  Lock lock(mutex);
  auto *h_ptr = group_bimap.retrieve_handle(group_id);
  if (!h_ptr) return false;
  *group_h = *h_ptr;
  return true;
}

bool
ActionProfMgr::retrieve_member_id(pi_indirect_handle_t member_h,
                                  Id *member_id) const {
  Lock lock(mutex);
  auto *id_ptr = member_bimap.retrieve_id(member_h);
  if (!id_ptr) return false;
  *member_id = *id_ptr;
  return true;
}

bool
ActionProfMgr::retrieve_group_id(pi_indirect_handle_t group_h,
                                 Id *group_id) const {
  Lock lock(mutex);
  auto *id_ptr = group_bimap.retrieve_id(group_h);
  if (!id_ptr) return false;
  *group_id = *id_ptr;
  return true;
}

/* static */
StatusOr<ActionProfMgr::PiApiChoice>
ActionProfMgr::choose_pi_api(pi_dev_id_t device_id) {
  int pi_api_support = pi_act_prof_api_support(device_id);
  if (pi_api_support & PI_ACT_PROF_API_SUPPORT_GRP_SET_MBRS) {
    return PiApiChoice::SET_MEMBERSHIP;
  } else if (pi_api_support & PI_ACT_PROF_API_SUPPORT_GRP_ADD_AND_REMOVE_MBR) {
    return PiApiChoice::INDIVIDUAL_ADDS_AND_REMOVES;
  }
  RETURN_ERROR_STATUS(Code::INTERNAL,
                      "Invalid return value from pi_act_prof_api_support");
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
