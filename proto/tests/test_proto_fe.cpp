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

#include <boost/functional/hash.hpp>

#include <gmock/gmock.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <string>
#include <fstream>  // std::ifstream
#include <cstring>  // std::memcmp
#include <iterator>  // std::distance

#include "PI/pi.h"
#include "PI/int/pi_int.h"
#include "PI/frontends/proto/device_mgr.h"

#include "p4info_to_and_from_proto.h"

#include "google/rpc/code.pb.h"

namespace pi {
namespace proto {
namespace testing {
namespace {

using pi::fe::proto::DeviceMgr;
using device_id_t = uint64_t;
using Code = ::google::rpc::Code;

class DummyMatchKey {
  friend struct DummyMatchKeyHash;
 public:
  explicit DummyMatchKey(const pi_match_key_t *match_key)
      : priority(match_key->priority),
        mk(&match_key->data[0], &match_key->data[match_key->data_size]) { }

  bool operator==(const DummyMatchKey& other) const {
    return priority == other.priority && mk == other.mk;
  }

  bool operator!=(const DummyMatchKey& other) const {
    return !(*this == other);
  }

 private:
  uint32_t priority;
  std::vector<char> mk;
};

struct DummyMatchKeyHash {
  std::size_t operator()(const DummyMatchKey& b) const {
    std::size_t seed = 0;
    boost::hash_combine(seed, b.priority);
    boost::hash_range(seed, b.mk.begin(), b.mk.end());
    return seed;
  }
};

struct ActionData {
  // define default constuctor for DummyTableEntry below
  ActionData() { }
  explicit ActionData(const pi_action_data_t *action_data)
      : data(&action_data->data[0],
             &action_data->data[action_data->data_size]) { }
  std::vector<char> data;
};

// TODO(antonin): support resources...
class DummyTableEntry {
 public:
  explicit DummyTableEntry(const pi_table_entry_t *table_entry)
      : type(table_entry->entry_type) {
    switch (table_entry->entry_type) {
      case PI_ACTION_ENTRY_TYPE_DATA:
        ad = ActionData(table_entry->entry.action_data);
        break;
      case PI_ACTION_ENTRY_TYPE_INDIRECT:
        indirect_h = table_entry->entry.indirect_handle;
        break;
      default:
        assert(0);
    }
  }

 private:
  pi_action_entry_type_t type;
  // not bothering with a union here
  ActionData ad;
  pi_indirect_handle_t indirect_h;
};

class DummyTable {
 public:
  pi_status_t entry_add(const pi_match_key_t *match_key,
                        const pi_table_entry_t *table_entry) {
    auto r = entries.emplace(DummyMatchKey(match_key),
                             DummyTableEntry(table_entry));
    // TODO(antonin): we need a better error code for duplicate entry
    return r.second ? PI_STATUS_SUCCESS : PI_STATUS_TARGET_ERROR;
  }

 private:
  std::unordered_map<DummyMatchKey, DummyTableEntry, DummyMatchKeyHash> entries;
};

class DummyActionProf {
 public:
  pi_status_t member_create(const pi_action_data_t *action_data,
                            pi_indirect_handle_t *mbr_handle) {
    members.emplace(member_counter, ActionData(action_data));
    *mbr_handle = member_counter++;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t member_modify(pi_indirect_handle_t mbr_handle,
                            const pi_action_data_t *action_data) {
    auto it = members.find(mbr_handle);
    if (it == members.end()) return PI_STATUS_TARGET_ERROR;
    it->second = ActionData(action_data);
    return PI_STATUS_SUCCESS;
  }

  pi_status_t member_delete(pi_indirect_handle_t mbr_handle) {
    auto count = members.erase(mbr_handle);
    return (count == 0) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

  pi_status_t group_create(size_t max_size, pi_indirect_handle_t *grp_handle) {
    (void) max_size;
    groups.emplace(group_counter, GroupMembers());
    *grp_handle = group_counter++;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t group_delete(pi_indirect_handle_t grp_handle) {
    auto count = groups.erase(grp_handle);
    return (count == 0) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

  pi_status_t group_add_member(pi_indirect_handle_t grp_handle,
                               pi_indirect_handle_t mbr_handle) {
    auto it = groups.find(grp_handle);
    if (it == groups.end()) return PI_STATUS_TARGET_ERROR;
    auto p = it->second.insert(mbr_handle);
    return (!p.second) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

  pi_status_t group_remove_member(pi_indirect_handle_t grp_handle,
                                  pi_indirect_handle_t mbr_handle) {
    auto it = groups.find(grp_handle);
    if (it == groups.end()) return PI_STATUS_TARGET_ERROR;
    auto count = it->second.erase(mbr_handle);
    return (count == 0) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

 private:
  using GroupMembers = std::unordered_set<pi_indirect_handle_t>;
  std::unordered_map<pi_indirect_handle_t, ActionData> members{};
  std::unordered_map<pi_indirect_handle_t, GroupMembers> groups{};
  size_t member_counter{0};
  size_t group_counter{1 << 24};
};

class DummySwitch {
 public:
  explicit DummySwitch(device_id_t device_id)
      : device_id(device_id) { }

  pi_status_t table_entry_add(pi_p4_id_t table_id,
                              const pi_match_key_t *match_key,
                              const pi_table_entry_t *table_entry) {
    // constructs DummyTable if not already in map
    return tables[table_id].entry_add(match_key, table_entry);
  }

  pi_status_t action_prof_member_create(pi_p4_id_t act_prof_id,
                                        const pi_action_data_t *action_data,
                                        pi_indirect_handle_t *mbr_handle) {
    // constructs DummyActionProf if not already in map
    return action_profs[act_prof_id].member_create(action_data, mbr_handle);
  }

  pi_status_t action_prof_member_modify(pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t mbr_handle,
                                        const pi_action_data_t *action_data) {
    return action_profs[act_prof_id].member_modify(mbr_handle, action_data);
  }

  pi_status_t action_prof_member_delete(pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t mbr_handle) {
    return action_profs[act_prof_id].member_delete(mbr_handle);
  }

  pi_status_t action_prof_group_create(pi_p4_id_t act_prof_id,
                                       size_t max_size,
                                       pi_indirect_handle_t *grp_handle) {
    return action_profs[act_prof_id].group_create(max_size, grp_handle);
  }

  pi_status_t action_prof_group_delete(pi_p4_id_t act_prof_id,
                                       pi_indirect_handle_t grp_handle) {
    return action_profs[act_prof_id].group_delete(grp_handle);
  }

  pi_status_t action_prof_group_add_member(pi_p4_id_t act_prof_id,
                                           pi_indirect_handle_t grp_handle,
                                           pi_indirect_handle_t mbr_handle) {
    return action_profs[act_prof_id].group_add_member(grp_handle, mbr_handle);
  }

  pi_status_t action_prof_group_remove_member(pi_p4_id_t act_prof_id,
                                           pi_indirect_handle_t grp_handle,
                                           pi_indirect_handle_t mbr_handle) {
    return action_profs[act_prof_id].group_remove_member(
        grp_handle, mbr_handle);
  }

 private:
  std::unordered_map<pi_p4_id_t, DummyTable> tables{};
  std::unordered_map<pi_p4_id_t, DummyActionProf> action_profs{};
  device_id_t device_id;
};

using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArg;
using ::testing::Truly;
using ::testing::Pointee;
using ::testing::AtLeast;

class DummySwitchMock : public DummySwitch {
 public:
  explicit DummySwitchMock(device_id_t device_id)
      : DummySwitch(device_id), sw(device_id) {
    // delegate calls to real object
    ON_CALL(*this, table_entry_add(_, _, _))
        .WillByDefault(Invoke(&sw, &DummySwitch::table_entry_add));

    // cannot use DoAll to combine 2 actions here (call to real object + handle
    // capture), because the handle needs to be captured after the delegated
    // call, but the delegated call is the one which needs to return the status
    ON_CALL(*this, action_prof_member_create(_, _, _))
        .WillByDefault(
            Invoke(this, &DummySwitchMock::_action_prof_member_create));
    ON_CALL(*this, action_prof_member_modify(_, _, _))
        .WillByDefault(Invoke(&sw, &DummySwitch::action_prof_member_modify));
    ON_CALL(*this, action_prof_member_delete(_, _))
        .WillByDefault(Invoke(&sw, &DummySwitch::action_prof_member_delete));
    // same comment as for action_prof_member_create above
    ON_CALL(*this, action_prof_group_create(_, _, _))
        .WillByDefault(
            Invoke(this, &DummySwitchMock::_action_prof_group_create));
    ON_CALL(*this, action_prof_group_delete(_, _))
        .WillByDefault(Invoke(&sw, &DummySwitch::action_prof_group_delete));
    ON_CALL(*this, action_prof_group_add_member(_, _, _))
        .WillByDefault(Invoke(&sw, &DummySwitch::action_prof_group_add_member));
    ON_CALL(*this, action_prof_group_remove_member(_, _, _))
        .WillByDefault(
            Invoke(&sw, &DummySwitch::action_prof_group_remove_member));
  }

  // used to capture handle for members
  pi_status_t _action_prof_member_create(pi_p4_id_t act_prof_id,
                                         const pi_action_data_t *action_data,
                                         pi_indirect_handle_t *h) {
    auto r = sw.action_prof_member_create(act_prof_id, action_data, h);
    if (r == PI_STATUS_SUCCESS) action_prof_h = *h;
    return r;
  }

  // used to capture handle for groups
  pi_status_t _action_prof_group_create(pi_p4_id_t act_prof_id, size_t max_size,
                                        pi_indirect_handle_t *h) {
    auto r = sw.action_prof_group_create(act_prof_id, max_size, h);
    if (r == PI_STATUS_SUCCESS) action_prof_h = *h;
    return r;
  }

  pi_indirect_handle_t get_action_prof_handle() const {
    return action_prof_h;
  }

  MOCK_METHOD3(table_entry_add,
               pi_status_t(pi_p4_id_t, const pi_match_key_t *,
                           const pi_table_entry_t *));

  MOCK_METHOD3(action_prof_member_create,
               pi_status_t(pi_p4_id_t, const pi_action_data_t *,
                           pi_indirect_handle_t *));
  MOCK_METHOD3(action_prof_member_modify,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t,
                           const pi_action_data_t *));
  MOCK_METHOD2(action_prof_member_delete,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t));
  MOCK_METHOD3(action_prof_group_create,
               pi_status_t(pi_p4_id_t, size_t, pi_indirect_handle_t *));
  MOCK_METHOD2(action_prof_group_delete,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t));
  MOCK_METHOD3(action_prof_group_add_member,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t,
                           pi_indirect_handle_t));
  MOCK_METHOD3(action_prof_group_remove_member,
               pi_status_t(pi_p4_id_t, pi_indirect_handle_t,
                           pi_indirect_handle_t));

 private:
  DummySwitch sw;
  pi_indirect_handle_t action_prof_h;
};

// used to map device ids to DummySwitchMock instances; thread safe in case we
// want to make tests run in parallel in the future
class DeviceResolver {
 public:
  static device_id_t new_switch() {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    auto id = r->device_id++;
    r->map.emplace(
        id, std::unique_ptr<DummySwitchMock>(new DummySwitchMock(id)));
    return id;
  }

  static DummySwitchMock *get_switch(device_id_t device_id) {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    return r->map.at(device_id).get();
  }

  static void release_switch(device_id_t device_id) {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    r->map.erase(device_id);
  }

 private:
  static DeviceResolver *get_instance() {
    static DeviceResolver resolver;
    return &resolver;
  }

  mutable std::mutex m{};
  std::unordered_map<device_id_t, std::unique_ptr<DummySwitchMock> > map{};
  device_id_t device_id{0};
};

class DummySwitchWrapper {
 public:
  DummySwitchWrapper() {
    _device_id = DeviceResolver::new_switch();
    _sw = DeviceResolver::get_switch(_device_id);
  }

  device_id_t device_id() { return _device_id; }

  DummySwitchMock *sw() { return _sw; }

  ~DummySwitchWrapper() {
    DeviceResolver::release_switch(_device_id);
  }

 private:
  device_id_t _device_id{0};
  DummySwitchMock *_sw{nullptr};
};

// here we implement the _pi_* methods which are needed for our tests
extern "C" {

pi_status_t _pi_init(void *) { return PI_STATUS_SUCCESS; }

pi_status_t _pi_destroy() { return PI_STATUS_SUCCESS; }

pi_status_t _pi_assign_device(pi_dev_id_t, const pi_p4info_t *,
                              pi_assign_extra_t *) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_remove_device(pi_dev_id_t) { return PI_STATUS_SUCCESS; }

pi_status_t _pi_session_init(pi_session_handle_t *) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_session_cleanup(pi_session_handle_t) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_add(pi_session_handle_t,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                int overwrite,
                                pi_entry_handle_t *) {
  (void)overwrite;
  return DeviceResolver::get_switch(dev_tgt.dev_id)->table_entry_add(
      table_id, match_key, table_entry);
}

// TODO(antonin)
// pi_status_t _pi_table_entries_fetch(pi_session_handle_t session_handle,
//                                     pi_dev_id_t dev_id, pi_p4_id_t table_id,
//                                     pi_table_fetch_res_t *res) {
//   (void)session_handle;
//   (void)dev_id;
//   (void)table_id;
//   (void)res;
//   return PI_STATUS_SUCCESS;
// }

// pi_status_t _pi_table_entries_fetch_done(pi_session_handle_t session_handle,
//                                          pi_table_fetch_res_t *res) {
//   (void)session_handle;
//   (void)res;
//   return PI_STATUS_SUCCESS;
// }

pi_status_t _pi_act_prof_mbr_create(pi_session_handle_t,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id,
                                    const pi_action_data_t *action_data,
                                    pi_indirect_handle_t *mbr_handle) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->action_prof_member_create(
      act_prof_id, action_data, mbr_handle);
}

pi_status_t _pi_act_prof_mbr_delete(pi_session_handle_t,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle) {
  return DeviceResolver::get_switch(dev_id)->action_prof_member_delete(
      act_prof_id, mbr_handle);
}

pi_status_t _pi_act_prof_mbr_modify(pi_session_handle_t,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle,
                                    const pi_action_data_t *action_data) {
  return DeviceResolver::get_switch(dev_id)->action_prof_member_modify(
      act_prof_id, mbr_handle, action_data);
}

pi_status_t _pi_act_prof_grp_create(pi_session_handle_t,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id, size_t max_size,
                                    pi_indirect_handle_t *grp_handle) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->action_prof_group_create(
      act_prof_id, max_size, grp_handle);
}

pi_status_t _pi_act_prof_grp_delete(pi_session_handle_t,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle) {
  return DeviceResolver::get_switch(dev_id)->action_prof_group_delete(
      act_prof_id, grp_handle);
}

pi_status_t _pi_act_prof_grp_add_mbr(pi_session_handle_t,
                                     pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                     pi_indirect_handle_t grp_handle,
                                     pi_indirect_handle_t mbr_handle) {
  return DeviceResolver::get_switch(dev_id)->action_prof_group_add_member(
      act_prof_id, grp_handle, mbr_handle);
}

pi_status_t _pi_act_prof_grp_remove_mbr(pi_session_handle_t,
                                        pi_dev_id_t dev_id,
                                        pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t grp_handle,
                                        pi_indirect_handle_t mbr_handle) {
  return DeviceResolver::get_switch(dev_id)->action_prof_group_remove_member(
      act_prof_id, grp_handle, mbr_handle);
}

}

// Google Test fixture for Protobuf Frontend tests
class DeviceMgrTest : public ::testing::Test {
 protected:
  DeviceMgrTest()
      : mock(wrapper.sw()), device_id(wrapper.device_id()), mgr(device_id) { }

  static void SetUpTestCase() {
    DeviceMgr::init(256);
    pi_add_config_from_file(input_path, PI_CONFIG_TYPE_BMV2_JSON, &p4info);
    p4info_proto = pi::p4info::p4info_serialize_to_proto(p4info);
  }

  static void TearDownTestCase() {
    pi_destroy_config(p4info);
    DeviceMgr::destroy();
  }

  void SetUp() override {
    p4::tmp::DeviceAssignRequest_Extras extras;
    mgr.init(p4info_proto, extras);
  }

  void TearDown() override { }

  static constexpr const char *input_path = TESTDATADIR "/" "unittest.json";
  static pi_p4info_t *p4info;
  static p4::config::P4Info p4info_proto;

  DummySwitchWrapper wrapper{};
  DummySwitchMock *mock;
  device_id_t device_id;
  DeviceMgr mgr;
};

pi_p4info_t *DeviceMgrTest::p4info = nullptr;
p4::config::P4Info DeviceMgrTest::p4info_proto;

class MatchTableTest : public DeviceMgrTest {
 protected:
  DeviceMgr::Status generic_add(pi_p4_id_t t_id, const p4::FieldMatch &mf,
                                const std::string &param_v);
  DeviceMgr::Status ExactOne_add(const std::string &mf_v,
                                 const std::string &param_v);
  DeviceMgr::Status LpmOne_add(const std::string &mf_v, unsigned int pLen,
                               const std::string &param_v);
  DeviceMgr::Status TernaryOne_add(const std::string &mf_v,
                                   const std::string &mask_v,
                                   const std::string &param_v);
};

DeviceMgr::Status
MatchTableTest::generic_add(pi_p4_id_t t_id, const p4::FieldMatch &mf,
                            const std::string &param_v) {
  p4::TableUpdate update;
  update.set_type(p4::TableUpdate_Type_INSERT);
  auto table_entry = update.mutable_table_entry();
  table_entry->set_table_id(t_id);
  auto mf_ptr = table_entry->add_match();
  *mf_ptr = mf;
  auto entry = table_entry->mutable_action();
  auto action = entry->mutable_action();
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  action->set_action_id(a_id);
  auto param = action->add_params();
  param->set_param_id(
      pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
  param->set_value(param_v);
  return mgr.table_write(update);
}

DeviceMgr::Status
MatchTableTest::ExactOne_add(const std::string &mf_v,
                             const std::string &param_v) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "ExactOne");
  p4::FieldMatch mf;
  mf.set_field_id(pi_p4info_field_id_from_name(p4info, "header_test.field32"));
  auto mf_exact = mf.mutable_exact();
  mf_exact->set_value(mf_v);
  return generic_add(t_id, mf, param_v);
}

DeviceMgr::Status
MatchTableTest::LpmOne_add(const std::string &mf_v, unsigned int pLen,
                           const std::string &param_v) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "LpmOne");
  p4::FieldMatch mf;
  mf.set_field_id(pi_p4info_field_id_from_name(p4info, "header_test.field32"));
  auto mf_lpm = mf.mutable_lpm();
  mf_lpm->set_value(mf_v);
  mf_lpm->set_prefix_len(pLen);
  return generic_add(t_id, mf, param_v);
}

DeviceMgr::Status
MatchTableTest::TernaryOne_add(const std::string &mf_v,
                               const std::string &mask_v,
                               const std::string &param_v) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "TernaryOne");
  p4::FieldMatch mf;
  mf.set_field_id(pi_p4info_field_id_from_name(p4info, "header_test.field32"));
  auto mf_lpm = mf.mutable_ternary();
  mf_lpm->set_value(mf_v);
  mf_lpm->set_mask(mask_v);
  return generic_add(t_id, mf, param_v);
}

// started out using a lambda in the test cases, but it was too much duplicated
// code
// TODO(antonin): build a matcher using googlemock base matchers (e.g. Field...)
// instead?
struct MatchKeyMatcher {
 public:
  MatchKeyMatcher(pi_p4_id_t t_id, const std::string &v)
      : t_id(t_id), v(v) { }

  bool operator()(const pi_match_key_t *mk) const {
    return (mk->table_id == t_id
            && mk->data_size == v.size()
            && !std::memcmp(mk->data, v.data(), v.size()));
  }

 private:
  pi_p4_id_t t_id;
  std::string v;
};

struct ActionDataMatcher {
 public:
  ActionDataMatcher(pi_p4_id_t a_id, const std::string &v)
      : a_id(a_id), v(v) { }

  bool operator()(const pi_action_data_t *action_data) const {
    return (action_data->action_id == a_id
            && action_data->data_size == v.size()
            && !std::memcmp(action_data->data, v.data(), v.size()));
  }

 private:
  pi_p4_id_t a_id;
  std::string v;
};

struct TableEntryMatcher_Direct {
 public:
  TableEntryMatcher_Direct(pi_p4_id_t a_id, const std::string &v)
      : action_data_matcher(a_id, v) { }

  bool operator()(const pi_table_entry_t *t_entry) const {
    if (t_entry->entry_type != PI_ACTION_ENTRY_TYPE_DATA) return false;
    const auto action_data = t_entry->entry.action_data;
    return action_data_matcher(action_data);
  }

 private:
  ActionDataMatcher action_data_matcher;
};

struct TableEntryMatcher_Indirect {
 public:
  explicit TableEntryMatcher_Indirect(pi_indirect_handle_t h)
      : h(h) { }

  bool operator()(const pi_table_entry_t *t_entry) const {
    if (t_entry->entry_type != PI_ACTION_ENTRY_TYPE_INDIRECT) return false;
    return (t_entry->entry.indirect_handle == h);
  }

 private:
  pi_indirect_handle_t h;
};

// TODO(antonin): maybe use value-parametrized tests to avoid code duplication,
// except if we are going to have some tests dependent on the match type

TEST_F(MatchTableTest, AddExact) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "ExactOne");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  // TODO(antonin): check for error if size not right
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mf));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher))
      .Times(2);
  DeviceMgr::Status status;
  status = ExactOne_add(mf, adata);
  ASSERT_EQ(status.code(), Code::OK);
  // second is error because duplicate match key
  status = ExactOne_add(mf, adata);
  ASSERT_NE(status.code(), Code::OK);
}

TEST_F(MatchTableTest, AddLpm) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "LpmOne");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  // TODO(antonin): check for error if size not right
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  // adding the pref length (12) in little endian format, over 4 bytes
  std::string mk = mf + std::string("\x0c\x00\x00\x00", 4);
  std::string adata(6, '\x00');
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mk));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher))
      .Times(2);
  DeviceMgr::Status status;
  status = LpmOne_add(mf, 12, adata);
  ASSERT_EQ(status.code(), Code::OK);
  // second is error because duplicate match key
  status = LpmOne_add(mf, 12, adata);
  ASSERT_NE(status.code(), Code::OK);
}

TEST_F(MatchTableTest, AddTernary) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "TernaryOne");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  // TODO(antonin): check for error if size not right
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string mask("\xff\x01\xf0\x0f", 4);
  // adding the mask
  std::string mk = mf + mask;
  std::string adata(6, '\x00');
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mk));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher))
      .Times(2);
  DeviceMgr::Status status;
  status = TernaryOne_add(mf, mask, adata);
  ASSERT_EQ(status.code(), Code::OK);
  // second is error because duplicate match key
  status = TernaryOne_add(mf, mask, adata);
  ASSERT_NE(status.code(), Code::OK);
}


class ActionProfTest : public DeviceMgrTest {
 protected:
  void set_action(p4::Action *action, const std::string &param_v) {
    auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    param->set_value(param_v);
  }

  p4::ActionProfileUpdate create_base_member_update(
      uint32_t member_id, const std::string &param_v) {
    p4::ActionProfileUpdate update;
    update.set_type(p4::ActionProfileUpdate_Type_CREATE);
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    auto entry = update.mutable_action_profile_entry();
    entry->set_action_profile_id(act_prof_id);
    auto member = entry->mutable_member();
    member->set_member_id(member_id);
    set_action(member->mutable_action(), param_v);
    return update;
  }

  void create_member(uint32_t member_id, const std::string &param_v) {
    auto update = create_base_member_update(member_id, param_v);
    auto status = mgr.action_profile_write(update);
    ASSERT_EQ(status.code(), Code::OK);
  }

  // create empty group
  p4::ActionProfileUpdate create_base_group_update(uint32_t group_id) {
    p4::ActionProfileUpdate update;
    update.set_type(p4::ActionProfileUpdate_Type_CREATE);
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    auto entry = update.mutable_action_profile_entry();
    entry->set_action_profile_id(act_prof_id);
    auto group = entry->mutable_group();
    group->set_group_id(group_id);
    return update;
  }
};

TEST_F(ActionProfTest, Member) {
  DeviceMgr::Status status;
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  uint32_t member_id_1 = 123, member_id_2 = 234;  // can be arbitrary
  std::string adata_1(6, '\x00');
  std::string adata_2(6, '\x11');
  auto ad_matcher_1 = Truly(ActionDataMatcher(a_id, adata_1));
  auto ad_matcher_2 = Truly(ActionDataMatcher(a_id, adata_2));

  // add one member
  p4::ActionProfileUpdate update;
  update.set_type(p4::ActionProfileUpdate_Type_CREATE);
  auto entry = update.mutable_action_profile_entry();
  entry->set_action_profile_id(act_prof_id);
  auto member = entry->mutable_member();
  member->set_member_id(member_id_1);
  set_action(member->mutable_action(), adata_1);
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, ad_matcher_1, _));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);
  auto mbr_h_1 = mock->get_action_prof_handle();

  // modify member
  set_action(member->mutable_action(), adata_2);
  update.set_type(p4::ActionProfileUpdate_Type_MODIFY);
  EXPECT_CALL(*mock, action_prof_member_modify(
      act_prof_id, mbr_h_1, ad_matcher_2));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);

  // add another member
  update.set_type(p4::ActionProfileUpdate_Type_CREATE);
  // use a different member id of course!
  member->set_member_id(member_id_2);
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, ad_matcher_2, _));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);
  auto mbr_h_2 = mock->get_action_prof_handle();
  ASSERT_NE(mbr_h_1, mbr_h_2);

  // delete both members
  update.set_type(p4::ActionProfileUpdate_Type_DELETE);
  member->set_member_id(member_id_1);
  EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, mbr_h_1));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);
  member->set_member_id(member_id_2);
  EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, mbr_h_2));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);
}

TEST_F(ActionProfTest, CreateDupMemberId) {
  DeviceMgr::Status status;
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t member_id = 123;
  std::string adata(6, '\x00');
  auto update = create_base_member_update(member_id, adata);
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _))
      .Times(AtLeast(1));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);
  status = mgr.action_profile_write(update);
  ASSERT_NE(status.code(), Code::OK);
}

TEST_F(ActionProfTest, BadMemberId) {
  DeviceMgr::Status status;
  uint32_t member_id = 123;
  std::string adata(6, '\x00');
  auto update = create_base_member_update(member_id, adata);
  // in this test we do not expect any call to a mock method
  // try to modify a member id which does not exist
  update.set_type(p4::ActionProfileUpdate_Type_MODIFY);
  status = mgr.action_profile_write(update);
  ASSERT_NE(status.code(), Code::OK);
  // try to delete a member id which does not exist
  update.set_type(p4::ActionProfileUpdate_Type_DELETE);
  status = mgr.action_profile_write(update);
  ASSERT_NE(status.code(), Code::OK);
}

TEST_F(ActionProfTest, Group) {
  DeviceMgr::Status status;
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t group_id = 1000;
  uint32_t member_id_1 = 1, member_id_2 = 2;

  // create 2 members
  std::string adata(6, '\x00');
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _))
      .Times(2);
  create_member(member_id_1, adata);
  auto mbr_h_1 = mock->get_action_prof_handle();
  create_member(member_id_2, adata);
  auto mbr_h_2 = mock->get_action_prof_handle();

  // create group with one member
  p4::ActionProfileUpdate update;
  update.set_type(p4::ActionProfileUpdate_Type_CREATE);
  auto entry = update.mutable_action_profile_entry();
  entry->set_action_profile_id(act_prof_id);
  auto group = entry->mutable_group();
  group->set_group_id(group_id);
  group->add_member_id(member_id_1);
  EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _));
  EXPECT_CALL(*mock, action_prof_group_add_member(act_prof_id, _, mbr_h_1));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);
  auto grp_h = mock->get_action_prof_handle();

  // add the same member, expect no call but valid operation
  update.set_type(p4::ActionProfileUpdate_Type_MODIFY);
  EXPECT_CALL(*mock, action_prof_group_add_member(_, _, _)).Times(0);
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);

  // add a second member
  group->add_member_id(member_id_2);
  EXPECT_CALL(*mock, action_prof_group_add_member(act_prof_id, grp_h, mbr_h_2));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);

  // remove one member
  group->clear_member_id(); group->add_member_id(member_id_2);
  EXPECT_CALL(*mock,
              action_prof_group_remove_member(act_prof_id, grp_h, mbr_h_1));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);

  // delete group, which has one remaining member
  update.set_type(p4::ActionProfileUpdate_Type_DELETE);
  group->clear_member_id();  // not needed
  EXPECT_CALL(*mock, action_prof_group_delete(act_prof_id, grp_h));
  // we do not expect a call to remove_member, the target is supposed to be able
  // to handle removing non-empty groups
  EXPECT_CALL(*mock, action_prof_group_remove_member(_, _, _)).Times(0);
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);
}

TEST_F(ActionProfTest, CreateDupGroupId) {
  DeviceMgr::Status status;
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t group_id = 1000;
  auto update = create_base_group_update(group_id);
  EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _))
      .Times(AtLeast(1));
  status = mgr.action_profile_write(update);
  ASSERT_EQ(status.code(), Code::OK);
  status = mgr.action_profile_write(update);
  ASSERT_NE(status.code(), Code::OK);
}

TEST_F(ActionProfTest, BadGroupId) {
  DeviceMgr::Status status;
  uint32_t group_id = 1000;
  auto update = create_base_group_update(group_id);
  // in this test we do not expect any call to a mock method
  // try to modify a group id which does not exist
  update.set_type(p4::ActionProfileUpdate_Type_MODIFY);
  status = mgr.action_profile_write(update);
  ASSERT_NE(status.code(), Code::OK);
  // try to delete a group id which does not exist
  update.set_type(p4::ActionProfileUpdate_Type_DELETE);
  status = mgr.action_profile_write(update);
  ASSERT_NE(status.code(), Code::OK);
}

TEST_F(ActionProfTest, AddBadMemberIdToGroup) {
  DeviceMgr::Status status;
  uint32_t group_id = 1000;
  uint32_t bad_member_id = 123;
  auto update = create_base_group_update(group_id);
  auto entry = update.mutable_action_profile_entry();
  auto group = entry->mutable_group();
  group->add_member_id(bad_member_id);
  EXPECT_CALL(*mock, action_prof_group_create(_, _, _));
  EXPECT_CALL(*mock, action_prof_group_add_member(_, _, _)).Times(0);
  status = mgr.action_profile_write(update);
  ASSERT_NE(status.code(), Code::OK);
}


class MatchTableIndirectTest : public DeviceMgrTest {
 protected:
  void create_member(uint32_t member_id, const std::string &param_v) {
    p4::ActionProfileUpdate update;
    update.set_type(p4::ActionProfileUpdate_Type_CREATE);
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
    auto entry = update.mutable_action_profile_entry();
    entry->set_action_profile_id(act_prof_id);
    auto member = entry->mutable_member();
    member->set_member_id(member_id);
    auto action = member->mutable_action();
    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    param->set_value(param_v);
    EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _));
    auto status = mgr.action_profile_write(update);
    ASSERT_EQ(status.code(), Code::OK);
  }

  // create a group which includes the provided members
  template <typename It>
  void create_group(uint32_t group_id, It first, It last) {
    p4::ActionProfileUpdate update;
    update.set_type(p4::ActionProfileUpdate_Type_CREATE);
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    auto entry = update.mutable_action_profile_entry();
    entry->set_action_profile_id(act_prof_id);
    auto group = entry->mutable_group();
    group->set_group_id(group_id);
    for (auto it = first; it != last; ++it) group->add_member_id(*it);
    EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _));
    EXPECT_CALL(*mock, action_prof_group_add_member(act_prof_id, _, _))
        .Times(std::distance(first, last));
    auto status = mgr.action_profile_write(update);
    ASSERT_EQ(status.code(), Code::OK);
  }

  void create_group(uint32_t group_id, uint32_t member_id) {
    create_group(group_id, &member_id, (&member_id) + 1);
  }

  DeviceMgr::Status add_indirect_entry_to_member(const std::string &mf_v,
                                                 uint32_t member_id) {
    return add_indirect_entry_common(mf_v, member_id, false);
  }

  DeviceMgr::Status add_indirect_entry_to_group(const std::string &mf_v,
                                                uint32_t group_id) {
    return add_indirect_entry_common(mf_v, group_id, true);
  }

 private:
  DeviceMgr::Status add_indirect_entry_common(const std::string &mf_v,
                                              uint32_t indirect_id,
                                              bool is_group) {
    p4::TableUpdate update;
    auto t_id = pi_p4info_table_id_from_name(p4info, "IndirectWS");
    update.set_type(p4::TableUpdate_Type_INSERT);
    auto table_entry = update.mutable_table_entry();
    table_entry->set_table_id(t_id);
    auto mf = table_entry->add_match();
    mf->set_field_id(
        pi_p4info_field_id_from_name(p4info, "header_test.field32"));
    auto mf_exact = mf->mutable_exact();
    mf_exact->set_value(mf_v);
    auto entry = table_entry->mutable_action();
    if (is_group)
      entry->set_action_profile_group_id(indirect_id);
    else
      entry->set_action_profile_member_id(indirect_id);
    return mgr.table_write(update);
  }
};

TEST_F(MatchTableIndirectTest, Member) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "IndirectWS");
  uint32_t member_id = 123;
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  create_member(member_id, adata);
  auto mbr_h = mock->get_action_prof_handle();
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mf));
  auto entry_matcher = Truly(TableEntryMatcher_Indirect(mbr_h));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher));
  auto status = add_indirect_entry_to_member(mf, member_id);
  ASSERT_EQ(status.code(), Code::OK);
}

TEST_F(MatchTableIndirectTest, Group) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "IndirectWS");
  uint32_t member_id = 123;
  uint32_t group_id = 1000;
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  create_member(member_id, adata);
  create_group(group_id, member_id);
  auto grp_h = mock->get_action_prof_handle();
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mf));
  auto entry_matcher = Truly(TableEntryMatcher_Indirect(grp_h));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher));
  auto status = add_indirect_entry_to_group(mf, group_id);
  ASSERT_EQ(status.code(), Code::OK);
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
