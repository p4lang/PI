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

#ifndef SRC_ACTION_PROF_MGR_H_
#define SRC_ACTION_PROF_MGR_H_

#include <PI/frontends/cpp/tables.h>
#include <PI/pi.h>

#include <map>
#include <mutex>
#include <set>
#include <unordered_map>
#include <vector>

#include "google/rpc/code.pb.h"
#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "common.h"

namespace pi {

namespace fe {

namespace proto {

using Code = ::google::rpc::Code;

template <typename T1, typename T2>
class BiMap {
 public:
  void add_mapping_1_2(const T1 &t1, const T2 &t2) {
    map_1_2.emplace(t1, t2);
    map_2_1.emplace(t2, t1);
  }

  // returns nullptr if no matching entry
  const T2 *get_from_1(const T1 &t1) const {
    auto it = map_1_2.find(t1);
    return (it == map_1_2.end()) ? nullptr : &it->second;
  }

  const T1 *get_from_2(const T2 &t2) const {
    auto it = map_2_1.find(t2);
    return (it == map_2_1.end()) ? nullptr : &it->second;
  }

  void remove_from_1(const T1 &t1) {
    map_1_2.erase(t1);
  }

  void remove_from_2(const T2 &t2) {
    map_2_1.erase(t2);
  }

 private:
  std::unordered_map<T1, T2> map_1_2{};
  std::unordered_map<T2, T1> map_2_1{};
};

class ActionProfBiMap {
 public:
  using Id = uint32_t;  // may change in the future

  void add(const Id &id, pi_indirect_handle_t h);

  // returns nullptr if no matching id
  const pi_indirect_handle_t *retrieve_handle(const Id &id) const;

  // returns nullptr if no matching handle
  const Id *retrieve_id(pi_indirect_handle_t h) const;

  void remove(const Id &id);

 private:
  BiMap<Id, pi_indirect_handle_t> bimap;
};

class ActionProfGroupMembership {
 public:
  using Id = ActionProfBiMap::Id;

  ActionProfGroupMembership();

  // in both cases, desired membership must be sorted
  std::vector<Id> compute_members_to_add(
      const std::vector<Id> &desired_membership) const;

  std::vector<Id> compute_members_to_remove(
      const std::vector<Id> &desired_membership) const;

  void add_member(const Id &member_id);
  void remove_member(const Id &member_id);

 private:
  std::set<Id> members{};
};

class ActionProfMgr {
  friend class ActionProfAccess;
 public:
  using Id = ActionProfBiMap::Id;
  using Status = ::google::rpc::Status;
  using SessionTemp = common::SessionTemp;

  ActionProfMgr(pi_dev_tgt_t device_tgt, pi_p4_id_t act_prof_id,
                pi_p4info_t *p4info);

  Status member_create(const p4::v1::ActionProfileMember &member,
                       const SessionTemp &session);

  Status group_create(const p4::v1::ActionProfileGroup &group,
                      const SessionTemp &session);

  Status member_modify(const p4::v1::ActionProfileMember &member,
                       const SessionTemp &session);

  Status group_modify(const p4::v1::ActionProfileGroup &group,
                      const SessionTemp &session);

  Status member_delete(const p4::v1::ActionProfileMember &member,
                       const SessionTemp &session);

  Status group_delete(const p4::v1::ActionProfileGroup &group,
                      const SessionTemp &session);

  // returns nullptr if no matching id
  const pi_indirect_handle_t *retrieve_member_handle(const Id &member_id);
  const pi_indirect_handle_t *retrieve_group_handle(const Id &group_id);

  const Id *retrieve_member_id(pi_indirect_handle_t h);
  const Id *retrieve_group_id(pi_indirect_handle_t h);

 private:
  bool check_p4_action_id(pi_p4_id_t p4_id) const;

  Status validate_action(const p4::v1::Action &action);
  pi::ActionData construct_action_data(const p4::v1::Action &action);

  // using RepeatedMembers = decltype(
  //     static_cast<p4::v1::ActionProfileGroup *>(nullptr)->member_id());
  Code group_update_members(pi::ActProf &ap,  // NOLINT(runtime/references)
                            const p4::v1::ActionProfileGroup &group);

  template <typename It>
  // NOLINTNEXTLINE(runtime/references)
  Code group_add_members(pi::ActProf &ap, const Id &group_id,
                         It first, It last) {
    for (auto it = first; it != last; ++it) {
      auto code = group_add_member(ap, group_id, *it);
      if (code != Code::OK) return code;
    }
    return Code::OK;
  }
  // NOLINTNEXTLINE(runtime/references)
  Code group_add_member(pi::ActProf &ap, const Id &group_id,
                        const Id &member_id);

  template <typename It>
  // NOLINTNEXTLINE(runtime/references)
  Code group_remove_members(pi::ActProf &ap, const Id &group_id,
                            It first, It last) {
    for (auto it = first; it != last; ++it) {
      auto code = group_remove_member(ap, group_id, *it);
      if (code != Code::OK) return code;
    }
    return Code::OK;
  }
  // NOLINTNEXTLINE(runtime/references)
  Code group_remove_member(pi::ActProf &ap, const Id &group_id,
                           const Id &member_id);

  // iterates over groups to remove member
  void update_group_membership(const Id &removed_member_id);

  using Mutex = std::mutex;
  using Lock = std::lock_guard<ActionProfMgr::Mutex>;
  pi_dev_tgt_t device_tgt;
  pi_p4_id_t act_prof_id;
  pi_p4info_t *p4info;
  ActionProfBiMap member_bimap{};
  ActionProfBiMap group_bimap{};
  std::map<Id, ActionProfGroupMembership> group_members{};
  mutable Mutex mutex{};
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_ACTION_PROF_MGR_H_
