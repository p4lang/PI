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

#include <PI/frontends/cpp/tables.h>
#include <PI/frontends/proto/device_mgr.h>
#include <PI/pi.h>

#include <memory>
#include <string>
#include <vector>

#include "google/rpc/code.pb.h"

#include "action_prof_mgr.h"
#include "common.h"
#include "p4info_to_and_from_proto.h"  // for p4info_proto_reader

#include "p4/tmp/p4config.pb.h"

namespace pi {

namespace fe {

namespace proto {

using device_id_t = DeviceMgr::device_id_t;
using p4_id_t = DeviceMgr::p4_id_t;
using Status = DeviceMgr::Status;
using PacketInCb = DeviceMgr::PacketInCb;
using Code = ::google::rpc::Code;
using common::SessionTemp;

// We don't yet have a mapping from PI error codes to ::google::rpc::Code
// values, so for now we almost always return UNKNOWN. It is likely that we will
// have our own error namespace (in addition to ::google::rpc::Code) anyway.

namespace {

// wraps the p4info pointer provided by the PI library into a unique_ptr
auto p4info_deleter = [](pi_p4info_t *p4info) {
  pi_destroy_config(p4info);
};
using P4InfoWrapper = std::unique_ptr<pi_p4info_t, decltype(p4info_deleter)>;

}  // namespace

class DeviceMgrImp {
 public:
  friend class DeviceMgr::counter_iterator;

  explicit DeviceMgrImp(device_id_t device_id)
      : device_id(device_id),
        device_tgt({static_cast<pi_dev_id_t>(device_id), 0xffff}) { }

  ~DeviceMgrImp() {
    pi_remove_device(device_id);
  }

  // we assume that the DeviceMgr client is smart enough here: for p4info
  // updates we do not do any locking; we assume that the client will not issue
  // table commands... while updating p4info
  void p4_change(pi_p4info_t *p4info_new) {
    action_profs.clear();
    for (auto act_prof_id = pi_p4info_act_prof_begin(p4info_new);
         act_prof_id != pi_p4info_act_prof_end(p4info_new);
         act_prof_id = pi_p4info_act_prof_next(p4info_new, act_prof_id)) {
      std::unique_ptr<ActionProfMgr> mgr(
          new ActionProfMgr(device_tgt, act_prof_id, p4info_new));
      action_profs.emplace(act_prof_id, std::move(mgr));
    }

    // we do this last, so that the ActProfMgr instances never point to an
    // invalid p4info, even though this is not strictly required here
    p4info.reset(p4info_new);
  }

  // TODO(antonin): we assume that VERIFY_AND_COMMIT is use for the first
  // pipeline_config_set, when no config has been pushed to the switch; while
  // VERIFY_AND_SAVE & COMMIT are used for config update. This is just
  // temporary.
  Status pipeline_config_set(p4::SetForwardingPipelineConfigRequest_Action a,
                             const p4::ForwardingPipelineConfig &config) {
    Status status;
    pi_status_t pi_status;
    status.set_code(Code::OK);
    if (a == p4::SetForwardingPipelineConfigRequest_Action_UNSPECIFIED) {
      status.set_code(Code::INVALID_ARGUMENT);
      return status;
    }

    pi_p4info_t *p4info_tmp = nullptr;
    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY ||
        a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_SAVE ||
        a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT) {
      if (!pi::p4info::p4info_proto_reader(config.p4info(), &p4info_tmp)) {
        status.set_code(Code::UNKNOWN);
        return status;
      }
    }

    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY)
      return status;

    p4::tmp::P4DeviceConfig p4_device_config;
    if (!p4_device_config.ParseFromString(config.p4_device_config())) {
      status.set_code(Code::INVALID_ARGUMENT);
      return status;
    }

    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT) {
      // this is temporary, until I can implement this method properly
      if (p4info) {
        pi_remove_device(device_id);
        action_profs.clear();
      }

      p4_change(p4info_tmp);
      std::vector<pi_assign_extra_t> assign_options;
      for (const auto &p : p4_device_config.extras().kv()) {
        pi_assign_extra_t e;
        e.key = p.first.c_str();
        e.v = p.second.c_str();
        e.end_of_extras = 0;
        assign_options.push_back(e);
      }
      assign_options.push_back({1, NULL, NULL});
      pi_status = pi_assign_device(device_id, p4info.get(),
                                   assign_options.data());
      if (pi_status != PI_STATUS_SUCCESS) status.set_code(Code::UNKNOWN);
      return status;
    }

    if (a == p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_SAVE) {
      const auto &device_data = p4_device_config.device_data();
      pi_status = pi_update_device_start(device_id, p4info_tmp,
                                         device_data.data(),
                                         device_data.size());
      if (pi_status != PI_STATUS_SUCCESS) {
        status.set_code(Code::UNKNOWN);
        pi_destroy_config(p4info_tmp);
        return status;
      }
      p4_change(p4info_tmp);
      return status;
    }

    assert(a == p4::SetForwardingPipelineConfigRequest_Action_COMMIT);
    pi_status = pi_update_device_end(device_id);
    if (pi_status != PI_STATUS_SUCCESS) status.set_code(Code::UNKNOWN);

    return status;
  }

  // TODO(antonin)
  Status pipeline_config_get(p4::ForwardingPipelineConfig *config) {
    (void) config;
    Status status;
    status.set_code(Code::UNIMPLEMENTED);
    return status;
  }

  Status init(const p4::config::P4Info &p4info_proto,
              const p4::tmp::DeviceAssignRequest_Extras &extras) {
    Status status;
    pi_status_t pi_status;
    std::vector<pi_assign_extra_t> assign_options;
    for (const auto &p : extras.kv()) {
      pi_assign_extra_t e;
      e.key = p.first.c_str();
      e.v = p.second.c_str();
      e.end_of_extras = 0;
      assign_options.push_back(e);
    }
    assign_options.push_back({1, NULL, NULL});
    pi_p4info_t *p4info_tmp = nullptr;
    if (!pi::p4info::p4info_proto_reader(p4info_proto, &p4info_tmp)) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    p4_change(p4info_tmp);
    pi_status = pi_assign_device(device_id, p4info.get(),
                                 assign_options.data());
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    status.set_code(Code::OK);
    return status;
  }

  Status update_start(const p4::config::P4Info &p4info_proto,
                      const std::string &device_data) {
    Status status;
    pi_status_t pi_status;
    pi_p4info_t *p4info_tmp = nullptr;
    if (!pi::p4info::p4info_proto_reader(p4info_proto, &p4info_tmp)) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    pi_status = pi_update_device_start(device_id, p4info_tmp,
                                       device_data.data(), device_data.size());
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      pi_destroy_config(p4info_tmp);
      return status;
    }
    p4_change(p4info_tmp);
    status.set_code(Code::OK);
    return status;
  }

  Status update_end() {
    Status status;
    auto pi_status = pi_update_device_end(device_id);
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    status.set_code(Code::OK);
    return status;
  }

  Status write(const p4::WriteRequest &request) {
    Status status;
    status.set_code(Code::OK);
    SessionTemp session(true  /* = batch */);
    for (const auto &update : request.updates()) {
      const auto &entity = update.entity();
      switch (entity.entity_case()) {
        case p4::Entity::kTableEntry:
          status = table_write_2(update.type(), entity.table_entry(), session);
          break;
        case p4::Entity::kActionProfileMember:
          status = action_profile_member_write_2(
              update.type(), entity.action_profile_member(), session);
          break;
        case p4::Entity::kActionProfileGroup:
          status = action_profile_group_write_2(
              update.type(), entity.action_profile_group(), session);
          break;
        case p4::Entity::kMeterEntry:
          status.set_code(Code::UNIMPLEMENTED);
          break;
        case p4::Entity::kCounterEntry:
          status.set_code(Code::UNIMPLEMENTED);
          break;
        default:
          status.set_code(Code::UNKNOWN);
          break;
      }
      if (status.code() != Code::OK) break;
    }
    return status;
  }

  Status read(const p4::ReadRequest &request,
              p4::ReadResponse *response) const {
    Status status;
    status.set_code(Code::OK);
    for (const auto &entity : request.entities()) {
      status = read_one(entity, response);
      if (status.code() != Code::OK) break;
    }
    return status;
  }

  Status read_one(const p4::Entity &entity, p4::ReadResponse *response) const {
    Status status;
    status.set_code(Code::OK);
    SessionTemp session(false  /* = batch */);
    switch (entity.entity_case()) {
      case p4::Entity::kTableEntry:
        status = table_read_2(entity.table_entry(), session, response);
        break;
      case p4::Entity::kActionProfileMember:
        status = action_profile_member_read_2(
            entity.action_profile_member(), session, response);
        break;
      case p4::Entity::kActionProfileGroup:
        status = action_profile_group_read_2(
            entity.action_profile_group(), session, response);
        break;
      case p4::Entity::kMeterEntry:
        status.set_code(Code::UNIMPLEMENTED);
        break;
      case p4::Entity::kCounterEntry:
        status = counter_read_2(entity.counter_entry(), session, response);
        break;
      default:
        status.set_code(Code::UNKNOWN);
        break;
    }
    return status;
  }

  Status table_write(const p4::TableUpdate &table_update) {
    Status status;
    SessionTemp session;
    switch (table_update.type()) {
      case p4::TableUpdate_Type_UNSPECIFIED:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
      case p4::TableUpdate_Type_INSERT:
        return table_insert(table_update.table_entry(), session);
      case p4::TableUpdate_Type_MODIFY:
        return table_modify(table_update.table_entry(), session);
      case p4::TableUpdate_Type_DELETE:
        return table_delete(table_update.table_entry(), session);
      default:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
    }
    return status;
  }

  Status table_write_2(p4::Update_Type update,
                       const p4::TableEntry &table_entry,
                       const SessionTemp &session) {
    Status status;
    switch (update) {
      case p4::Update_Type_UNSPECIFIED:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
      case p4::Update_Type_INSERT:
        return table_insert(table_entry, session);
      case p4::Update_Type_MODIFY:
        return table_modify(table_entry, session);
      case p4::Update_Type_DELETE:
        return table_delete(table_entry, session);
      default:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
    }
    return status;
  }

  Code parse_match_key(p4_id_t table_id, const pi_match_key_t *match_key,
                       p4::TableEntry *entry) const {
    auto num_match_fields = pi_p4info_table_num_match_fields(
        p4info.get(), table_id);
    MatchKeyReader mk_reader(match_key);
    auto priority = mk_reader.get_priority();
    if (priority > 0) entry->set_priority(priority);
    for (size_t j = 0; j < num_match_fields; j++) {
      auto finfo = pi_p4info_table_match_field_info(p4info.get(), table_id, j);
      auto mf = entry->add_match();
      mf->set_field_id(finfo->mf_id);
      switch (finfo->match_type) {
        case PI_P4INFO_MATCH_TYPE_VALID:
          {
            auto valid = mf->mutable_valid();
            bool value;
            mk_reader.get_valid(finfo->mf_id, &value);
            valid->set_value(value);
          }
          break;
        case PI_P4INFO_MATCH_TYPE_EXACT:
          {
            auto exact = mf->mutable_exact();
            mk_reader.get_exact(finfo->mf_id, exact->mutable_value());
          }
          break;
        case PI_P4INFO_MATCH_TYPE_LPM:
          {
            auto lpm = mf->mutable_lpm();
            int pLen;
            mk_reader.get_lpm(finfo->mf_id, lpm->mutable_value(), &pLen);
            lpm->set_prefix_len(pLen);
          }
          break;
        case PI_P4INFO_MATCH_TYPE_TERNARY:
          {
            auto ternary = mf->mutable_ternary();
            mk_reader.get_ternary(finfo->mf_id, ternary->mutable_value(),
                                  ternary->mutable_mask());
          }
          break;
        case PI_P4INFO_MATCH_TYPE_RANGE:
          return Code::UNIMPLEMENTED;
        default:
          return Code::UNKNOWN;
      }
    }
    return Code::OK;
  }

  Code parse_action_data(const pi_action_data_t *pi_action_data,
                         p4::Action *action) const {
    ActionDataReader reader(pi_action_data);
    auto action_id = reader.get_action_id();
    action->set_action_id(action_id);
    size_t num_params;
    auto param_ids = pi_p4info_action_get_params(
        p4info.get(), action_id, &num_params);
    for (size_t j = 0; j < num_params; j++) {
      auto param = action->add_params();
      param->set_param_id(param_ids[j]);
      reader.get_arg(param_ids[j], param->mutable_value());
    }
    return Code::OK;
  }

  Code parse_action_entry(p4_id_t table_id, const pi_table_entry_t *pi_entry,
                          p4::TableEntry *entry) const {
    if (pi_entry->entry_type == PI_ACTION_ENTRY_TYPE_NONE) return Code::OK;

    auto table_action = entry->mutable_action();
    if (pi_entry->entry_type == PI_ACTION_ENTRY_TYPE_INDIRECT) {
      auto indirect_h = pi_entry->entry.indirect_handle;
      auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                               table_id);
      // check that table is indirect
      if (action_prof_id == PI_INVALID_ID) return Code::UNKNOWN;
      auto action_prof_mgr = get_action_prof_mgr(action_prof_id);
      auto member_id = action_prof_mgr->retrieve_member_id(indirect_h);
      if (member_id != nullptr) {
        table_action->set_action_profile_member_id(*member_id);
        return Code::OK;
      }
      auto group_id = action_prof_mgr->retrieve_group_id(indirect_h);
      if (group_id == nullptr) return Code::UNKNOWN;
      table_action->set_action_profile_group_id(*group_id);
      return Code::OK;
    }

    return parse_action_data(pi_entry->entry.action_data,
                             table_action->mutable_action());
  }

  // An is a functor which will be called on entries and needs to append a new
  // p4::TableEntry to entries and return a pointer to it
  template <typename T, typename Accessor>
  Status table_read_common(p4_id_t table_id, const SessionTemp &session,
                           T *entries, Accessor An) const {
    Status status;
    pi_table_fetch_res_t *res;
    auto pi_status = pi_table_entries_fetch(session.get(), device_id,
                                            table_id, &res);
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }
    auto num_entries = pi_table_entries_num(res);
    pi_table_ma_entry_t entry;
    pi_entry_handle_t entry_handle;
    Code code = Code::OK;
    for (size_t i = 0; i < num_entries; i++) {
      pi_table_entries_next(res, &entry, &entry_handle);
      auto table_entry = An(entries);
      table_entry->set_table_id(table_id);
      code = parse_match_key(table_id, entry.match_key, table_entry);
      if (code != Code::OK) break;
      code = parse_action_entry(table_id, &entry.entry, table_entry);
      if (code != Code::OK) break;
    }

    pi_table_entries_fetch_done(session.get(), res);

    status.set_code(code);
    return status;
  }

  // TODO(antonin): default entry? direct resources?
  Status table_read(p4_id_t table_id,
                    std::vector<p4::TableEntry> *entries) const {
    SessionTemp session;
    return table_read_common(
        table_id, session, entries,
        [] (decltype(entries) e) { e->emplace_back(); return &e->back(); });
  }

  Status table_read_all(std::vector<p4::TableEntry> *entries) const {
    Status status;
    status.set_code(Code::OK);
    for (auto t_id = pi_p4info_table_begin(p4info.get());
         t_id != pi_p4info_table_end(p4info.get());
         t_id = pi_p4info_table_next(p4info.get(), t_id)) {
      status = table_read(t_id, entries);
      if (status.code() != Code::OK) break;
    }
    return status;
  }

  Status table_read_one_2(p4_id_t table_id, const SessionTemp &session,
                          p4::ReadResponse *response) const {
    return table_read_common(
        table_id, session, response,
        [] (decltype(response) r) {
          return r->add_entities()->mutable_table_entry(); });
  }

  // TODO(antonin): full filtering on the match key, action, ...
  Status table_read_2(const p4::TableEntry &table_entry,
                      const SessionTemp &session,
                      p4::ReadResponse *response) const {
    Status status;
    status.set_code(Code::OK);
    if (table_entry.table_id() == 0) {  // read all entries for all tables
      for (auto t_id = pi_p4info_table_begin(p4info.get());
           t_id != pi_p4info_table_end(p4info.get());
           t_id = pi_p4info_table_next(p4info.get(), t_id)) {
        status = table_read_one_2(t_id, session, response);
        if (status.code() != Code::OK) break;
      }
    } else {  // read for a single table
      status = table_read_one_2(table_entry.table_id(), session, response);
    }
    return status;
  }

  Status action_profile_write(
      const p4::ActionProfileUpdate &action_profile_update) {
    Status status;
    const auto &entry = action_profile_update.action_profile_entry();
    auto update_type = action_profile_update.type();
    switch (update_type) {
      case p4::ActionProfileUpdate_Type_CREATE:
        return action_profile_create(entry);
      case p4::ActionProfileUpdate_Type_MODIFY:
        return action_profile_modify(entry);
      case p4::ActionProfileUpdate_Type_DELETE:
        return action_profile_delete(entry);
      default:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
    }
    return status;
  }

  Status action_profile_member_write_2(p4::Update_Type update,
                                       const p4::ActionProfileMember &member,
                                       const SessionTemp &session) {
    Status status;
    auto action_prof_mgr = get_action_prof_mgr(member.action_profile_id());
    if (action_prof_mgr == nullptr) {
      status.set_code(Code::INVALID_ARGUMENT);
      return status;
    }
    switch (update) {
      case p4::Update_Type_UNSPECIFIED:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
      case p4::Update_Type_INSERT:
        return action_prof_mgr->member_create(member, session);
      case p4::Update_Type_MODIFY:
        return action_prof_mgr->member_modify(member, session);
      case p4::Update_Type_DELETE:
        return action_prof_mgr->member_delete(member, session);
      default:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
    }
    return status;
  }

  Status action_profile_group_write_2(p4::Update_Type update,
                                      const p4::ActionProfileGroup &group,
                                      const SessionTemp &session) {
    Status status;
    auto action_prof_mgr = get_action_prof_mgr(group.action_profile_id());
    if (action_prof_mgr == nullptr) {
      status.set_code(Code::INVALID_ARGUMENT);
      return status;
    }
    switch (update) {
      case p4::Update_Type_UNSPECIFIED:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
      case p4::Update_Type_INSERT:
        return action_prof_mgr->group_create(group, session);
      case p4::Update_Type_MODIFY:
        return action_prof_mgr->group_modify(group, session);
      case p4::Update_Type_DELETE:
        return action_prof_mgr->group_delete(group, session);
      default:
        status.set_code(Code::INVALID_ARGUMENT);
        break;
    }
    return status;
  }

  template <typename T, typename MemberAccessor, typename GroupAccessor>
  Status action_profile_read_common(
      p4_id_t action_profile_id, const SessionTemp &session,
      T *entries, MemberAccessor MAn, GroupAccessor GAn) const {
    Status status;
    Code code(Code::OK);

    auto action_prof_mgr = get_action_prof_mgr(action_profile_id);
    if (action_prof_mgr == nullptr) {
      status.set_code(Code::INVALID_ARGUMENT);
      return status;
    }

    pi_act_prof_fetch_res_t *res;
    auto pi_status = pi_act_prof_entries_fetch(session.get(), device_id,
                                               action_profile_id, &res);
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }

    auto num_members = pi_act_prof_mbrs_num(res);
    for (size_t i = 0; i < num_members; i++) {
      pi_action_data_t *action_data;
      pi_indirect_handle_t member_h;
      auto member = MAn(entries);
      if (member == nullptr) break;
      member->set_action_profile_id(action_profile_id);
      pi_act_prof_mbrs_next(res, &action_data, &member_h);
      code = parse_action_data(action_data, member->mutable_action());
      if (code != Code::OK) break;
      auto member_id = action_prof_mgr->retrieve_member_id(member_h);
      if (member_id == nullptr) {
        code = Code::UNKNOWN;
        break;
      }
      member->set_member_id(*member_id);
    }

    auto num_groups = pi_act_prof_grps_num(res);
    for (size_t i = 0; i < num_groups; i++) {
      pi_indirect_handle_t *members_h;
      size_t num;
      pi_indirect_handle_t group_h;
      auto group = GAn(entries);
      if (group == nullptr) break;
      group->set_action_profile_id(action_profile_id);
      pi_act_prof_grps_next(res, &members_h, &num, &group_h);
      auto group_id = action_prof_mgr->retrieve_group_id(group_h);
      if (group_id == nullptr) {
        code = Code::UNKNOWN;
        break;
      }
      group->set_group_id(*group_id);
      for (size_t j = 0; j < num; j++) {
        auto member_id = action_prof_mgr->retrieve_member_id(members_h[j]);
        if (member_id == nullptr) {
          code = Code::UNKNOWN;
          break;
        }
        auto member = group->add_members();
        member->set_member_id(*member_id);
      }
    }

    pi_act_prof_entries_fetch_done(session.get(), res);

    status.set_code(code);
    return status;
  }

  Status action_profile_read(
      p4_id_t action_profile_id,
      std::vector<p4::ActionProfileEntry> *entries) const {
    SessionTemp session;
    auto push_entry = [action_profile_id](decltype(entries) entries) {
      entries->emplace_back();
      auto entry = &entries->back();
      entry->set_action_profile_id(action_profile_id);
      return entry;
    };
    return action_profile_read_common(
        action_profile_id, session, entries,
        [&push_entry] (decltype(entries) e) {
          return push_entry(e)->mutable_member(); },
        [&push_entry] (decltype(entries) e) {
          return push_entry(e)->mutable_group(); });
  }

  Status action_profile_read_all(
      std::vector<p4::ActionProfileEntry> *entries) const {
    Status status;
    status.set_code(Code::OK);
    for (auto act_prof_id = pi_p4info_act_prof_begin(p4info.get());
         act_prof_id != pi_p4info_act_prof_end(p4info.get());
         act_prof_id = pi_p4info_act_prof_next(p4info.get(), act_prof_id)) {
      status = action_profile_read(act_prof_id, entries);
      if (status.code() != Code::OK) break;
    }
    return status;
  }

  Status action_profile_member_read_one_2(p4_id_t action_profile_id,
                                          const SessionTemp &session,
                                          p4::ReadResponse *response) const {
    return action_profile_read_common(
        action_profile_id, session, response,
        [] (decltype(response) r) {
          return r->add_entities()->mutable_action_profile_member(); },
        [] (decltype(response)) -> p4::ActionProfileGroup * {
          return nullptr; });
  }

  // TODO(antonin): full filtering
  Status action_profile_member_read_2(const p4::ActionProfileMember &member,
                                      const SessionTemp &session,
                                      p4::ReadResponse *response) const {
    Status status;
    status.set_code(Code::OK);
    if (member.action_profile_id() == 0) {
      for (auto act_prof_id = pi_p4info_act_prof_begin(p4info.get());
           act_prof_id != pi_p4info_act_prof_end(p4info.get());
           act_prof_id = pi_p4info_act_prof_next(p4info.get(), act_prof_id)) {
        status = action_profile_member_read_one_2(act_prof_id, session,
                                                  response);
        if (status.code() != Code::OK) break;
      }
    } else {
      status = action_profile_member_read_one_2(
          member.action_profile_id(), session, response);
    }
    return status;
  }

  Status action_profile_group_read_one_2(p4_id_t action_profile_id,
                                          const SessionTemp &session,
                                          p4::ReadResponse *response) const {
    return action_profile_read_common(
        action_profile_id, session, response,
        [] (decltype(response)) -> p4::ActionProfileMember * {
          return nullptr; },
        [] (decltype(response) r) {
          return r->add_entities()->mutable_action_profile_group(); });
  }

  // TODO(antonin): full filtering
  Status action_profile_group_read_2(const p4::ActionProfileGroup &group,
                                     const SessionTemp &session,
                                     p4::ReadResponse *response) const {
    Status status;
    status.set_code(Code::OK);
    if (group.action_profile_id() == 0) {
      for (auto act_prof_id = pi_p4info_act_prof_begin(p4info.get());
           act_prof_id != pi_p4info_act_prof_end(p4info.get());
           act_prof_id = pi_p4info_act_prof_next(p4info.get(), act_prof_id)) {
        status = action_profile_group_read_one_2(act_prof_id, session,
                                                 response);
        if (status.code() != Code::OK) break;
      }
    } else {
      status = action_profile_group_read_one_2(
          group.action_profile_id(), session, response);
    }
    return status;
  }

  Status packet_out_send(const std::string &packet) const {
    Status status;
    auto pi_status = pi_packetout_send(device_id, packet.data(), packet.size());
    if (pi_status != PI_STATUS_SUCCESS)
      status.set_code(Code::UNKNOWN);
    else
      status.set_code(Code::OK);
    return status;
  }

  void packet_in_register_cb(PacketInCb cb, void *cookie) {
    cb_ = std::move(cb);
    cookie_ = cookie;
    pi_packetin_register_cb(device_id, &DeviceMgrImp::packet_in_cb,
                            static_cast<void *>(this));
  }

  // TODO(antonin)
  Status counter_write(const p4::CounterEntry &entry) {
    (void) entry;
    return Status();
  }

  Status counter_read(p4::CounterEntry *entry) const {
    Status status;
    auto counter_id = entry->counter_id();
    auto is_direct = (pi_p4info_counter_get_direct(p4info.get(), counter_id)
                      != PI_INVALID_ID);
    if (is_direct) {  // TODO(antonin)
      status.set_code(Code::UNIMPLEMENTED);
      return status;
    }
    SessionTemp session;
    if (entry->cells().empty()) {
      auto counter_size = pi_p4info_counter_get_size(p4info.get(), counter_id);
      for (size_t index = 0; index < counter_size; index++) {
        auto cell = entry->add_cells();
        cell->set_index(index);
        auto code = counter_read_one_index(session, counter_id, cell);
        if (code != Code::OK) {
          status.set_code(code);
          return status;
        }
      }
    } else {
      for (auto &cell : *entry->mutable_cells()) {
        auto code = counter_read_one_index(session, counter_id, &cell);
        if (code != Code::OK) {
          status.set_code(code);
          return status;
        }
      }
    }
    status.set_code(Code::OK);
    return status;
  }

  Status counter_read_one_2(p4_id_t counter_id,
                            const p4::CounterEntry &counter_entry,
                            const SessionTemp &session,
                            p4::ReadResponse *response) const {
    Status status;
    status.set_code(Code::OK);
    auto is_direct = (pi_p4info_counter_get_direct(p4info.get(), counter_id)
                      != PI_INVALID_ID);
    if (is_direct) {  // TODO(antonin)
      status.set_code(Code::UNIMPLEMENTED);
      return status;
    }
    if (counter_entry.type_case() == p4::CounterEntry::kTableEntry) {
      status.set_code(Code::INVALID_ARGUMENT);
      return status;
    }
    if (counter_entry.type_case() == p4::CounterEntry::kIndex) {
      auto entry = response->add_entities()->mutable_counter_entry();
      entry->CopyFrom(counter_entry);
      auto code = counter_read_one_index(session, counter_id, entry);
      if (code != Code::OK) status.set_code(code);
      return status;
    }
    // no index, read all
    auto counter_size = pi_p4info_counter_get_size(p4info.get(), counter_id);
    for (size_t index = 0; index < counter_size; index++) {
      auto entry = response->add_entities()->mutable_counter_entry();
      entry->set_index(index);
      auto code = counter_read_one_index(session, counter_id, entry);
      if (code != Code::OK) {
        status.set_code(code);
        return status;
      }
    }
    return status;
  }

  Status counter_read_2(const p4::CounterEntry &counter_entry,
                        const SessionTemp &session,
                        p4::ReadResponse *response) const {
    Status status;
    status.set_code(Code::OK);
    if (counter_entry.counter_id() == 0) {  // read all entries for all counters
      for (auto c_id = pi_p4info_counter_begin(p4info.get());
           c_id != pi_p4info_counter_end(p4info.get());
           c_id = pi_p4info_counter_next(p4info.get(), c_id)) {
        status = counter_read_one_2(c_id, counter_entry, session, response);
        if (status.code() != Code::OK) break;
      }
    } else {  // read for a single counter
      status = counter_read_one_2(counter_entry.counter_id(), counter_entry,
                                  session, response);
    }
    return status;
  }

  static void init(size_t max_devices) {
    assert(pi_init(max_devices, NULL) == PI_STATUS_SUCCESS);
  }

  static void destroy() {
    pi_destroy();
  }

 private:
  Code construct_match_key(const p4::TableEntry &entry,
                           pi::MatchKey *match_key) const {
    for (const auto &mf : entry.match()) {
      switch (mf.field_match_type_case()) {
        case p4::FieldMatch::kExact:
          match_key->set_exact(mf.field_id(), mf.exact().value().data(),
                               mf.exact().value().size());
          break;
        case p4::FieldMatch::kLpm:
          match_key->set_lpm(mf.field_id(), mf.lpm().value().data(),
                             mf.lpm().value().size(), mf.lpm().prefix_len());
          break;
        case p4::FieldMatch::kTernary:
          if (mf.ternary().value().size() != mf.ternary().mask().size())
            return Code::INVALID_ARGUMENT;
          match_key->set_ternary(mf.field_id(), mf.ternary().value().data(),
                                 mf.ternary().mask().data(),
                                 mf.ternary().value().size());
          break;
        case p4::FieldMatch::kValid:
          match_key->set_valid(mf.field_id(), mf.valid().value());
          break;
        case p4::FieldMatch::kRange:
          return Code::UNIMPLEMENTED;
        default:
          return Code::INVALID_ARGUMENT;
      }
    }
    return Code::OK;
  }

  Code construct_action_data(const p4::Action &action,
                             pi::ActionEntry *action_entry) {
    action_entry->init_action_data(p4info.get(), action.action_id());
    auto action_data = action_entry->mutable_action_data();
    for (const auto &p : action.params()) {
      action_data->set_arg(p.param_id(), p.value().data(), p.value().size());
    }
    return Code::OK;
  }

  Code construct_action_entry_indirect(uint32_t table_id,
                                       const p4::TableAction &table_action,
                                       pi::ActionEntry *action_entry) {
    auto action_prof_id = pi_p4info_table_get_implementation(p4info.get(),
                                                             table_id);
    // check that table is indirect
    if (action_prof_id == PI_INVALID_ID) return Code::INVALID_ARGUMENT;
    auto action_prof_mgr = get_action_prof_mgr(action_prof_id);
    // cannot assert because the action prof id is provided by the PI
    assert(action_prof_mgr);
    const pi_indirect_handle_t *indirect_h = nullptr;
    switch (table_action.type_case()) {
      case p4::TableAction::kActionProfileMemberId:
        indirect_h = action_prof_mgr->retrieve_member_handle(
            table_action.action_profile_member_id());
        break;
      case p4::TableAction::kActionProfileGroupId:
        indirect_h = action_prof_mgr->retrieve_group_handle(
            table_action.action_profile_group_id());
        break;
      default:
        assert(0);
    }
    // invalid member/group id
    if (indirect_h == nullptr) return Code::INVALID_ARGUMENT;
    action_entry->init_indirect_handle(*indirect_h);
    return Code::OK;
  }

  // the table_id is needed for indirect entries
  Code construct_action_entry(uint32_t table_id,
                              const p4::TableAction &table_action,
                              pi::ActionEntry *action_entry) {
    switch (table_action.type_case()) {
      case p4::TableAction::kAction:
        return construct_action_data(table_action.action(), action_entry);
      case p4::TableAction::kActionProfileMemberId:
      case p4::TableAction::kActionProfileGroupId:
        return construct_action_entry_indirect(table_id, table_action,
                                               action_entry);
      default:
        return Code::INVALID_ARGUMENT;
    }
  }

  Status table_insert(const p4::TableEntry &table_entry,
                      const SessionTemp &session) {
    Status status;
    Code code;
    const auto table_id = table_entry.table_id();
    pi::MatchKey match_key(p4info.get(), table_id);
    code = construct_match_key(table_entry, &match_key);
    if (code != Code::OK) {
      status.set_code(code);
      return status;
    }

    pi::ActionEntry action_entry;
    code = construct_action_entry(
        table_id, table_entry.action(), &action_entry);
    if (code != Code::OK) {
      status.set_code(code);
      return status;
    }

    pi::MatchTable mt(session.get(), device_tgt, p4info.get(), table_id);
    pi_status_t pi_status;
    // an empty match means default entry
    if (table_entry.match().empty()) {
      pi_status = mt.default_entry_set(action_entry);
    } else {
      pi_entry_handle_t handle;
      pi_status = mt.entry_add(match_key, action_entry, false, &handle);
      // handle is not used as this frontend do all operations using match key
      (void) handle;
    }
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }

    status.set_code(Code::OK);
    return status;
  }

  Status table_modify(const p4::TableEntry &table_entry,
                      const SessionTemp &session) {
    (void) table_entry;
    (void) session;
    Status status;
    status.set_code(Code::UNIMPLEMENTED);
    return status;
  }

  Status table_delete(const p4::TableEntry &table_entry,
                      const SessionTemp &session) {
    Status status;
    Code code;
    const auto table_id = table_entry.table_id();
    pi::MatchKey match_key(p4info.get(), table_id);
    code = construct_match_key(table_entry, &match_key);
    if (code != Code::OK) {
      status.set_code(code);
      return status;
    }

    pi::MatchTable mt(session.get(), device_tgt, p4info.get(), table_id);
    pi_status_t pi_status;
    // an empty match means default entry
    if (table_entry.match().empty()) {
      // we do not yet have the ability to clear a default entry, which is not a
      // very interesting feature anyway
      status.set_code(Code::UNIMPLEMENTED);
      return status;
    } else {
      pi_status = mt.entry_delete_wkey(match_key);
    }
    if (pi_status != PI_STATUS_SUCCESS) {
      status.set_code(Code::UNKNOWN);
      return status;
    }

    status.set_code(Code::OK);
    return status;
  }

  ActionProfMgr *get_action_prof_mgr(uint32_t id) const {
    auto it = action_profs.find(id);
    return (it == action_profs.end()) ? nullptr : it->second.get();
  }

  ActionProfMgr *get_action_prof_mgr(const p4::ActionProfileEntry &entry) {
    return get_action_prof_mgr(entry.action_profile_id());
  }

  // this function to avoid code duplication
  // we can probably simplify this code if the action_profile_id is moved up in
  // p4runtime.proto
  template <typename FMember, typename FGroup>
  Status action_profile_common(const p4::ActionProfileEntry &entry,
                               FMember fmember, FGroup fgroup) {
    Status status;
    auto action_prof_mgr = get_action_prof_mgr(entry);
    if (action_prof_mgr == nullptr) {
      status.set_code(Code::INVALID_ARGUMENT);
      return status;
    }
    SessionTemp session;
    switch (entry.type_case()) {
      case p4::ActionProfileEntry::kMember:
        return (action_prof_mgr->*fmember)(entry.member(), session);
      case p4::ActionProfileEntry::kGroup:
        return (action_prof_mgr->*fgroup)(entry.group(), session);
      default:  // cannot happen (caught by get_action_prof_mgr)
        assert(0);
    }
  }

  Status action_profile_create(const p4::ActionProfileEntry &entry) {
    return action_profile_common(
        entry, &ActionProfMgr::member_create, &ActionProfMgr::group_create);
  }

  Status action_profile_modify(const p4::ActionProfileEntry &entry) {
    return action_profile_common(
        entry, &ActionProfMgr::member_modify, &ActionProfMgr::group_modify);
  }

  Status action_profile_delete(const p4::ActionProfileEntry &entry) {
    return action_profile_common(
        entry, &ActionProfMgr::member_delete, &ActionProfMgr::group_delete);
  }

  template <typename T>
  Code counter_read_one_index(const SessionTemp &session, uint32_t counter_id,
                              T *cell) const {
    auto index = cell->index();
    int flags = PI_COUNTER_FLAGS_NONE;
    pi_counter_data_t counter_data;
    pi_status_t pi_status = pi_counter_read(session.get(), device_tgt,
                                            counter_id, index, flags,
                                            &counter_data);
    if (pi_status != PI_STATUS_SUCCESS) return Code::UNKNOWN;
    auto data = cell->mutable_data();
    if (counter_data.valid & PI_COUNTER_UNIT_PACKETS)
      data->set_packet_count(counter_data.packets);
    if (counter_data.valid & PI_COUNTER_UNIT_BYTES)
      data->set_byte_count(counter_data.bytes);
    return Code::OK;
  }

  static void packet_in_cb(pi_dev_id_t dev_id, const char *pkt, size_t size,
                           void *cookie) {
    auto mgr = static_cast<DeviceMgrImp *>(cookie);
    assert(dev_id == mgr->device_id);
    mgr->cb_(mgr->device_id, std::string(pkt, size), mgr->cookie_);
  }

  device_id_t device_id;
  // for now, we assume all possible pipes of device are programmed in the same
  // way
  pi_dev_tgt_t device_tgt;
  P4InfoWrapper p4info{nullptr, p4info_deleter};

  PacketInCb cb_;
  void *cookie_;

  // ActionProfMgr is not movable because of mutex
  std::unordered_map<pi_p4_id_t, std::unique_ptr<ActionProfMgr> >
  action_profs{};
};

DeviceMgr::DeviceMgr(device_id_t device_id) {
  pimp = std::unique_ptr<DeviceMgrImp>(new DeviceMgrImp(device_id));
}

DeviceMgr::~DeviceMgr() { }

// PIMPL forwarding

Status
DeviceMgr::pipeline_config_set(
    p4::SetForwardingPipelineConfigRequest_Action action,
    const p4::ForwardingPipelineConfig &config) {
  return pimp->pipeline_config_set(action, config);
}

Status
DeviceMgr::pipeline_config_get(p4::ForwardingPipelineConfig *config) {
  return pimp->pipeline_config_get(config);
}

Status
DeviceMgr::init(const p4::config::P4Info &p4info,
                const p4::tmp::DeviceAssignRequest_Extras &extras) {
  return pimp->init(p4info, extras);
}

Status
DeviceMgr::update_start(const p4::config::P4Info &p4info,
                        const std::string &device_data) {
  return pimp->update_start(p4info, device_data);
}

Status
DeviceMgr::update_end() {
  return pimp->update_end();
}

Status
DeviceMgr::write(const p4::WriteRequest &request) {
  return pimp->write(request);
}

Status
DeviceMgr::read(const p4::ReadRequest &request,
                p4::ReadResponse *response) const {
  return pimp->read(request, response);
}

Status
DeviceMgr::read_one(const p4::Entity &entity,
                    p4::ReadResponse *response) const {
  return pimp->read_one(entity, response);
}

Status
DeviceMgr::table_write(const p4::TableUpdate &table_update) {
  return pimp->table_write(table_update);
}

Status
DeviceMgr::table_read(p4_id_t table_id,
                      std::vector<p4::TableEntry> *entries) const {
  return pimp->table_read(table_id, entries);
}

Status
DeviceMgr::table_read_all(std::vector<p4::TableEntry> *entries) const {
  return pimp->table_read_all(entries);
}

Status
DeviceMgr::action_profile_write(
    const p4::ActionProfileUpdate &action_profile_update) {
  return pimp->action_profile_write(action_profile_update);
}

Status
DeviceMgr::action_profile_read(
    p4_id_t action_profile_id,
    std::vector<p4::ActionProfileEntry> *entries) const {
  return pimp->action_profile_read(action_profile_id, entries);
}

Status
DeviceMgr::action_profile_read_all(
    std::vector<p4::ActionProfileEntry> *entries) const {
  return pimp->action_profile_read_all(entries);
}

Status
DeviceMgr::packet_out_send(const std::string &packet) const {
  return pimp->packet_out_send(packet);
}

void
DeviceMgr::packet_in_register_cb(PacketInCb cb, void *cookie) {
  return pimp->packet_in_register_cb(cb, cookie);
}

Status
DeviceMgr::counter_write(const p4::CounterEntry &entry) {
  return pimp->counter_write(entry);
}

Status
DeviceMgr::counter_read(p4::CounterEntry *entry) const {
  return pimp->counter_read(entry);
}

void
DeviceMgr::init(size_t max_devices) {
  DeviceMgrImp::init(max_devices);
}

void
DeviceMgr::destroy() {
  DeviceMgrImp::destroy();
}

DeviceMgr::counter_iterator
DeviceMgr::counter_read_begin() const {
  return counter_iterator(pimp.get(), counter_iterator::InitState::BEGIN);
}

DeviceMgr::counter_iterator
DeviceMgr::counter_read_end() const {
  return counter_iterator(pimp.get(), counter_iterator::InitState::END);
}


void
DeviceMgr::counter_iterator::counter_read() {
  auto p4info = device_mgr->p4info.get();
  if (counter_id == pi_p4info_counter_end(p4info)) {
    entry = nullptr;
    return;
  }
  entry->set_counter_id(counter_id);
  entry->clear_cells();
  auto status = device_mgr->counter_read(entry.get());
  assert(status.code() == Code::OK);
}

DeviceMgr::counter_iterator::counter_iterator(const DeviceMgrImp *device_mgr,
                                              InitState init)
    : device_mgr(device_mgr), counter_id(PI_INVALID_ID), entry(nullptr) {
  if (init == InitState::BEGIN) {
    entry = std::make_shared<p4::CounterEntry>();
    auto p4info = device_mgr->p4info.get();
    counter_id = pi_p4info_counter_begin(p4info);
    counter_read();
  }
}

p4::CounterEntry &
DeviceMgr::counter_iterator::operator*() const {
  assert(entry != nullptr && "Invalid iterator dereference.");
  return *entry.get();
}

p4::CounterEntry *
DeviceMgr::counter_iterator::operator->() const {
  assert(entry != nullptr && "Invalid iterator dereference.");
  return entry.get();
}

bool
DeviceMgr::counter_iterator::operator==(const counter_iterator &other) const {
  return (device_mgr == other.device_mgr) && (counter_id == other.counter_id);
}

bool
DeviceMgr::counter_iterator::operator!=(const counter_iterator &other) const {
  return !(*this == other);
}

DeviceMgr::counter_iterator &
DeviceMgr::counter_iterator::operator++() {
  assert(entry != nullptr && "Out-of-bounds iterator increment.");
  auto p4info = device_mgr->p4info.get();
  counter_id = pi_p4info_counter_next(p4info, counter_id);
  counter_read();
  return *this;
}

const DeviceMgr::counter_iterator
DeviceMgr::counter_iterator::operator++(int) {  // NOLINT(readability/function)
  // Use operator++()
  const counter_iterator old(*this);
  ++(*this);
  return old;
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
