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

#include <google/protobuf/util/message_differencer.h>

#include <algorithm>  // std::copy
#include <fstream>  // std::ifstream
#include <iterator>  // std::distance
#include <memory>
#include <mutex>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <cstring>  // std::memcmp

#include "PI/frontends/proto/device_mgr.h"
#include "PI/int/pi_int.h"
#include "PI/int/serialize.h"
#include "PI/pi.h"
#include "PI/proto/util.h"

#include "p4info_to_and_from_proto.h"

#include "google/rpc/code.pb.h"

namespace pi {
namespace proto {
namespace testing {
namespace {

using pi::fe::proto::DeviceMgr;
using device_id_t = uint64_t;
using Code = ::google::rpc::Code;

using google::protobuf::util::MessageDifferencer;

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

  size_t emit(char *dst) const {
    size_t s = 0;
    s += emit_uint32(dst, priority);
    std::copy(mk.begin(), mk.end(), dst + s);
    s += mk.size();
    return s;
  }

  size_t nbytes() const {
    return mk.size();
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

class ActionData {
 public:
  // define default constuctor for DummyTableEntry below
  ActionData() { }
  explicit ActionData(const pi_action_data_t *action_data)
      : action_id(action_data->action_id),
        data(&action_data->data[0],
             &action_data->data[action_data->data_size]) { }

  size_t emit(char *dst) const {
    size_t s = 0;
    s += emit_p4_id(dst, action_id);
    s += emit_uint32(dst + s, data.size());
    std::copy(data.begin(), data.end(), dst + s);
    s += data.size();
    return s;
  }

 private:
  pi_p4_id_t action_id;
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

  size_t emit(char *dst) const {
    size_t s = 0;
    s += emit_action_entry_type(dst, type);
    switch (type) {
      case PI_ACTION_ENTRY_TYPE_NONE:
        break;
      case PI_ACTION_ENTRY_TYPE_DATA:
        s += ad.emit(dst + s);
        break;
      case PI_ACTION_ENTRY_TYPE_INDIRECT:
        s += emit_indirect_handle(dst + s, indirect_h);
        break;
    }
    return s;
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

  pi_status_t entries_fetch(pi_table_fetch_res_t *res) {
    res->num_entries = entries.size();
    // TODO(antonin): it does not make much sense to me anymore for it to be the
    // target's responsibility to populate this field
    res->mkey_nbytes = 0;
    char *buf = new char[16384];  // should be large enough for testing
    char *buf_ptr = buf;
    size_t count = 0;
    for (const auto &p : entries) {
      buf_ptr += emit_entry_handle(buf_ptr, count++);
      res->mkey_nbytes = p.first.nbytes();
      buf_ptr += p.first.emit(buf_ptr);
      buf_ptr += p.second.emit(buf_ptr);
      buf_ptr += emit_uint32(buf_ptr, 0);  // direct resources
    }
    res->entries = buf;
    res->entries_size = std::distance(buf, buf_ptr);
    return PI_STATUS_SUCCESS;
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

  pi_status_t entries_fetch(pi_act_prof_fetch_res_t *res) {
    res->num_members = members.size();
    res->num_groups = groups.size();
    constexpr size_t kBufSize = 16384;  // should be large enough for testing
    // members
    {
      char *buf = new char[kBufSize];
      char *buf_ptr = buf;
      for (const auto &p : members) {
        buf_ptr += emit_indirect_handle(buf_ptr, p.first);
        buf_ptr += p.second.emit(buf_ptr);
      }
      res->entries_members = buf;
      res->entries_members_size = std::distance(buf, buf_ptr);
    }
    // groups
    {
      char *buf = new char[kBufSize];
      char *buf_ptr = buf;
      res->mbr_handles = new pi_indirect_handle_t[kBufSize];
      res->num_cumulated_mbr_handles = 0;
      size_t offset = 0;
      for (const auto &p : groups) {
        buf_ptr += emit_indirect_handle(buf_ptr, p.first);
        auto &mbrs = p.second;
        buf_ptr += emit_uint32(buf_ptr, mbrs.size());
        buf_ptr += emit_uint32(buf_ptr, res->num_cumulated_mbr_handles);
        res->num_cumulated_mbr_handles += mbrs.size();
        for (const auto &m : mbrs) res->mbr_handles[offset++] = m;
      }
      res->entries_groups = buf;
      res->entries_groups_size = std::distance(buf, buf_ptr);
    }
    return PI_STATUS_SUCCESS;
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

  pi_status_t table_entries_fetch(pi_p4_id_t table_id,
                                  pi_table_fetch_res_t *res) {
    return tables[table_id].entries_fetch(res);
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

  pi_status_t action_prof_entries_fetch(pi_p4_id_t act_prof_id,
                                        pi_act_prof_fetch_res_t *res) {
    return action_profs[act_prof_id].entries_fetch(res);
  }

 private:
  std::unordered_map<pi_p4_id_t, DummyTable> tables{};
  std::unordered_map<pi_p4_id_t, DummyActionProf> action_profs{};
#ifdef __clang__
  __attribute__((unused))
#endif
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
    ON_CALL(*this, table_entries_fetch(_, _))
        .WillByDefault(Invoke(&sw, &DummySwitch::table_entries_fetch));

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
    ON_CALL(*this, action_prof_entries_fetch(_, _))
        .WillByDefault(Invoke(&sw, &DummySwitch::action_prof_entries_fetch));
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
  MOCK_METHOD2(table_entries_fetch,
               pi_status_t(pi_p4_id_t, pi_table_fetch_res_t *));

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
  MOCK_METHOD2(action_prof_entries_fetch,
               pi_status_t(pi_p4_id_t, pi_act_prof_fetch_res_t *));

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

pi_status_t _pi_batch_begin(pi_session_handle_t) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_batch_end(pi_session_handle_t, bool) {
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

pi_status_t _pi_table_entries_fetch(pi_session_handle_t,
                                    pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res) {
  return DeviceResolver::get_switch(dev_id)->table_entries_fetch(
      table_id, res);
}

pi_status_t _pi_table_entries_fetch_done(pi_session_handle_t,
                                         pi_table_fetch_res_t *res) {
  delete[] res->entries;
  return PI_STATUS_SUCCESS;
}

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

pi_status_t _pi_act_prof_entries_fetch(pi_session_handle_t,
                                       pi_dev_id_t dev_id,
                                       pi_p4_id_t act_prof_id,
                                       pi_act_prof_fetch_res_t *res) {
  return DeviceResolver::get_switch(dev_id)->action_prof_entries_fetch(
      act_prof_id, res);
}

pi_status_t _pi_act_prof_entries_fetch_done(pi_session_handle_t,
                                            pi_act_prof_fetch_res_t *res) {
  delete[] res->entries_members;
  delete[] res->entries_groups;
  delete[] res->mbr_handles;
  return PI_STATUS_SUCCESS;
}

}

// Google Test fixture for Protobuf Frontend tests
class DeviceMgrTest : public ::testing::Test {
  // apparently cannot be "protected" because of the use of WithParamInterface
  // in one of the subclasses
 public:
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
    p4::ForwardingPipelineConfig config;
    config.set_allocated_p4info(&p4info_proto);
    auto status = mgr.pipeline_config_set(
        p4::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT,
        config);
    ASSERT_EQ(status.code(), Code::OK);
    config.release_p4info();
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

TEST_F(DeviceMgrTest, ResourceTypeFromId) {
  using Type = pi::proto::util::P4ResourceType;
  using pi::proto::util::resource_type_from_id;
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  ASSERT_EQ(Type::ACTION, resource_type_from_id(a_id));
  auto t_id = pi_p4info_table_id_from_name(p4info, "ExactOne");
  ASSERT_EQ(Type::TABLE, resource_type_from_id(t_id));
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  ASSERT_EQ(Type::ACTION_PROFILE, resource_type_from_id(act_prof_id));
  auto c_id = pi_p4info_counter_id_from_name(p4info, "ExactOne_counter");
  ASSERT_EQ(Type::COUNTER, resource_type_from_id(c_id));
  auto m_id = pi_p4info_meter_id_from_name(p4info, "ExactOne_meter");
  ASSERT_EQ(Type::METER, resource_type_from_id(m_id));
  ASSERT_EQ(Type::INVALID,
            resource_type_from_id(pi::proto::util::invalid_id()));
}

using ::testing::WithParamInterface;
using ::testing::Values;
using ::testing::Combine;

class MatchKeyInput {
 public:
  explicit MatchKeyInput(const std::string &mf_v) : mf(mf_v) { }
  MatchKeyInput(const std::string &mf_v, const std::string &mask_v)
      : mf(mf_v), mask(mask_v) { }
  MatchKeyInput(const std::string &mf_v, const std::string &mask_v, int pri)
      : mf(mf_v), mask(mask_v), priority(pri) { }
  MatchKeyInput(const std::string &mf_v, unsigned int pLen)
      : mf(mf_v), pLen(pLen) { }

  std::string get_match_key() const {
    std::string mk(mf);
    mk += mask;
    if (pLen > 0) {
      std::string pLen_str(4, '\x00');
      pLen_str[0] = static_cast<char>(pLen);
      mk += pLen_str;
    }
    return mk;
  }

  p4::FieldMatch get_proto(pi_p4_id_t f_id) const {
    p4::FieldMatch fm;
    fm.set_field_id(f_id);
    if (mask != "") {
      auto ternary = fm.mutable_ternary();
      ternary->set_value(mf);
      ternary->set_mask(mask);
    } else if (pLen > 0) {
      auto lpm = fm.mutable_lpm();
      lpm->set_value(mf);
      lpm->set_prefix_len(pLen);
    } else {
      auto exact = fm.mutable_exact();
      exact->set_value(mf);
    }
    return fm;
  }

  // The MatchKeyInput object is used to parametrize the MatchTableTest test
  // below. If I do not define this operator, valgrind reports some memory
  // errors regarding "uninitialised values" because of the compiler padding
  // MatchKeyInput and gtest trying to print the binary data of the object using
  // sizeof.
  friend std::ostream &operator<<(std::ostream &out, const MatchKeyInput &mki) {
    (void) mki;
    return out;
  }

 private:
  std::string mf;
  std::string mask{""};
  unsigned int pLen{0};
  int priority{0};
};

class MatchTableTest
    : public DeviceMgrTest,
      public WithParamInterface<std::tuple<const char *, MatchKeyInput> > {
 protected:
  p4::TableEntry generic_make(pi_p4_id_t t_id, const p4::FieldMatch &mf,
                              const std::string &param_v);

  DeviceMgr::Status add_one(p4::TableEntry *entry);
};

DeviceMgr::Status
MatchTableTest::add_one(p4::TableEntry *entry) {
  p4::WriteRequest request;
  auto update = request.add_updates();
  update->set_type(p4::Update_Type_INSERT);
  auto entity = update->mutable_entity();
  entity->set_allocated_table_entry(entry);
  auto status = mgr.write(request);
  entity->release_table_entry();
  return status;
}

p4::TableEntry
MatchTableTest::generic_make(pi_p4_id_t t_id, const p4::FieldMatch &mf,
                             const std::string &param_v) {
  p4::TableEntry table_entry;
  table_entry.set_table_id(t_id);
  auto mf_ptr = table_entry.add_match();
  *mf_ptr = mf;
  auto entry = table_entry.mutable_action();
  auto action = entry->mutable_action();
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  action->set_action_id(a_id);
  auto param = action->add_params();
  param->set_param_id(
      pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
  param->set_value(param_v);
  return table_entry;
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

TEST_P(MatchTableTest, AddAndRead) {
  auto t_id = pi_p4info_table_id_from_name(p4info, std::get<0>(GetParam()));
  auto mf_id = pi_p4info_table_match_field_id_from_name(
      p4info, t_id, "header_test.field32");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mk_input.get_match_key()));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher))
      .Times(2);
  DeviceMgr::Status status;
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata);
  status = add_one(&entry);
  ASSERT_EQ(status.code(), Code::OK);
  // second is error because duplicate match key
  status = add_one(&entry);
  ASSERT_NE(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  p4::ReadResponse response;
  p4::Entity entity;
  auto table_entry = entity.mutable_table_entry();
  table_entry->set_table_id(t_id);
  status = mgr.read_one(entity, &response);
  ASSERT_EQ(status.code(), Code::OK);
  const auto &entities = response.entities();
  ASSERT_EQ(1, entities.size());
  ASSERT_TRUE(MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
}

#define MK std::string("\xaa\xbb\xcc\xdd", 4)
#define MASK std::string("\xff\x01\xf0\x0f", 4)
#define PREF_LEN 12

INSTANTIATE_TEST_CASE_P(
    MatchTableTypes, MatchTableTest,
    Values(std::make_tuple("ExactOne", MatchKeyInput(MK)),
           std::make_tuple("LpmOne", MatchKeyInput(MK, PREF_LEN)),
           std::make_tuple("TernaryOne", MatchKeyInput(MK, MASK))));

#undef MK
#undef MASK
#undef PREF_LEN


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

  p4::ActionProfileMember make_member(uint32_t member_id,
                                      const std::string &param_v = "") {
    p4::ActionProfileMember member;
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    member.set_action_profile_id(act_prof_id);
    member.set_member_id(member_id);
    set_action(member.mutable_action(), param_v);
    return member;
  }

  template <typename T>
  DeviceMgr::Status write_member(T type, p4::ActionProfileMember *member) {
    p4::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(type);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_member(member);
    auto status = mgr.write(request);
    entity->release_action_profile_member();
    return status;
  }

  DeviceMgr::Status create_member(p4::ActionProfileMember *member) {
    return write_member(p4::Update_Type_INSERT, member);
  }

  DeviceMgr::Status modify_member(p4::ActionProfileMember *member) {
    return write_member(p4::Update_Type_MODIFY, member);
  }

  DeviceMgr::Status delete_member(p4::ActionProfileMember *member) {
    return write_member(p4::Update_Type_DELETE, member);
  }

  void add_member_to_group(p4::ActionProfileGroup *group, uint32_t member_id) {
    auto member = group->add_members();
    member->set_member_id(member_id);
  }

  template <typename It>
  p4::ActionProfileGroup make_group(uint32_t group_id,
                                    It members_begin, It members_end) {
    p4::ActionProfileGroup group;
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    group.set_action_profile_id(act_prof_id);
    group.set_group_id(group_id);
    for (auto it = members_begin; it != members_end; ++it) {
      auto member = group.add_members();
      member->set_member_id(*it);
    }
    return group;
  }

  p4::ActionProfileGroup make_group(uint32_t group_id) {
    std::vector<uint32_t> members;
    return make_group(group_id, members.begin(), members.end());
  }

  template <typename T>
  DeviceMgr::Status write_group(T type, p4::ActionProfileGroup *group) {
    p4::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(type);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_group(group);
    auto status = mgr.write(request);
    entity->release_action_profile_group();
    return status;
  }

  DeviceMgr::Status create_group(p4::ActionProfileGroup *group) {
    return write_group(p4::Update_Type_INSERT, group);
  }

  DeviceMgr::Status modify_group(p4::ActionProfileGroup *group) {
    return write_group(p4::Update_Type_MODIFY, group);
  }

  DeviceMgr::Status delete_group(p4::ActionProfileGroup *group) {
    return write_group(p4::Update_Type_DELETE, group);
  }
};

TEST_F(ActionProfTest, Member) {
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  uint32_t member_id_1 = 123, member_id_2 = 234;  // can be arbitrary
  std::string adata_1(6, '\x00');
  std::string adata_2(6, '\x11');
  auto ad_matcher_1 = Truly(ActionDataMatcher(a_id, adata_1));
  auto ad_matcher_2 = Truly(ActionDataMatcher(a_id, adata_2));

  // add one member
  auto member_1 = make_member(member_id_1, adata_1);
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, ad_matcher_1, _));
  EXPECT_EQ(create_member(&member_1).code(), Code::OK);
  auto mbr_h_1 = mock->get_action_prof_handle();

  // modify member
  member_1 = make_member(member_id_1, adata_2);
  EXPECT_CALL(*mock, action_prof_member_modify(
      act_prof_id, mbr_h_1, ad_matcher_2));
  EXPECT_EQ(modify_member(&member_1).code(), Code::OK);

  // add another member
  auto member_2 = make_member(member_id_2, adata_2);
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, ad_matcher_2, _));
  EXPECT_EQ(create_member(&member_2).code(), Code::OK);
  auto mbr_h_2 = mock->get_action_prof_handle();
  ASSERT_NE(mbr_h_1, mbr_h_2);

  // delete both members
  EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, mbr_h_1));
  EXPECT_EQ(delete_member(&member_1).code(), Code::OK);
  EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, mbr_h_2));
  EXPECT_EQ(delete_member(&member_2).code(), Code::OK);
}

TEST_F(ActionProfTest, CreateDupMemberId) {
  DeviceMgr::Status status;
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t member_id = 123;
  std::string adata(6, '\x00');
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _))
      .Times(AtLeast(1));
  auto member = make_member(member_id, adata);
  EXPECT_EQ(create_member(&member).code(), Code::OK);
  EXPECT_NE(create_member(&member).code(), Code::OK);
}

TEST_F(ActionProfTest, BadMemberId) {
  DeviceMgr::Status status;
  uint32_t member_id = 123;
  std::string adata(6, '\x00');
  // in this test we do not expect any call to a mock method
  auto member = make_member(member_id, adata);
  // try to modify a member id which does not exist
  EXPECT_NE(modify_member(&member).code(), Code::OK);
  // try to delete a member id which does not exist
  EXPECT_NE(delete_member(&member).code(), Code::OK);
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
  auto member_1 = make_member(member_id_1, adata);
  EXPECT_EQ(create_member(&member_1).code(), Code::OK);
  auto mbr_h_1 = mock->get_action_prof_handle();
  auto member_2 = make_member(member_id_2, adata);
  EXPECT_EQ(create_member(&member_2).code(), Code::OK);
  auto mbr_h_2 = mock->get_action_prof_handle();

  // create group with one member
  auto group = make_group(group_id);
  add_member_to_group(&group, member_id_1);
  EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _));
  EXPECT_CALL(*mock, action_prof_group_add_member(act_prof_id, _, mbr_h_1));
  ASSERT_EQ(create_group(&group).code(), Code::OK);
  auto grp_h = mock->get_action_prof_handle();

  // add the same member, expect no call but valid operation
  EXPECT_CALL(*mock, action_prof_group_add_member(_, _, _)).Times(0);
  ASSERT_EQ(modify_group(&group).code(), Code::OK);

  // add a second member
  add_member_to_group(&group, member_id_2);
  EXPECT_CALL(*mock, action_prof_group_add_member(act_prof_id, grp_h, mbr_h_2));
  ASSERT_EQ(modify_group(&group).code(), Code::OK);

  // remove one member
  group.clear_members();
  add_member_to_group(&group, member_id_2);
  EXPECT_CALL(*mock,
              action_prof_group_remove_member(act_prof_id, grp_h, mbr_h_1));
  ASSERT_EQ(modify_group(&group).code(), Code::OK);

  // delete group, which has one remaining member
  group.clear_members();  // not needed
  EXPECT_CALL(*mock, action_prof_group_delete(act_prof_id, grp_h));
  // we do not expect a call to remove_member, the target is supposed to be able
  // to handle removing non-empty groups
  EXPECT_CALL(*mock, action_prof_group_remove_member(_, _, _)).Times(0);
  ASSERT_EQ(delete_group(&group).code(), Code::OK);
}

TEST_F(ActionProfTest, Read) {
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t group_id = 1000;
  uint32_t member_id_1 = 1;

  // create 1 member
  std::string adata(6, '\x00');
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _));
  auto member_1 = make_member(member_id_1, adata);
  EXPECT_EQ(create_member(&member_1).code(), Code::OK);

  auto mbr_h_1 = mock->get_action_prof_handle();

  // create group with one member
  auto group = make_group(group_id);
  add_member_to_group(&group, member_id_1);
  EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _));
  EXPECT_CALL(*mock, action_prof_group_add_member(act_prof_id, _, mbr_h_1));
  ASSERT_EQ(create_group(&group).code(), Code::OK);

  EXPECT_CALL(*mock, action_prof_entries_fetch(act_prof_id, _)).Times(2);
  p4::ReadResponse response;
  p4::ReadRequest request;
  {
    auto entity = request.add_entities();
    auto member = entity->mutable_action_profile_member();
    member->set_action_profile_id(act_prof_id);
  }
  {
    auto entity = request.add_entities();
    auto group = entity->mutable_action_profile_group();
    group->set_action_profile_id(act_prof_id);
  }
  ASSERT_EQ(mgr.read(request, &response).code(), Code::OK);
  const auto &entities = response.entities();
  ASSERT_EQ(2, entities.size());
  ASSERT_TRUE(MessageDifferencer::Equals(
      member_1, entities.Get(0).action_profile_member()));
}

TEST_F(ActionProfTest, CreateDupGroupId) {
  DeviceMgr::Status status;
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t group_id = 1000;
  auto group = make_group(group_id);
  EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _))
      .Times(AtLeast(1));
  EXPECT_EQ(create_group(&group).code(), Code::OK);
  EXPECT_NE(create_group(&group).code(), Code::OK);
}

TEST_F(ActionProfTest, BadGroupId) {
  DeviceMgr::Status status;
  uint32_t group_id = 1000;
  auto group = make_group(group_id);
  // in this test we do not expect any call to a mock method
  // try to modify a group id which does not exist
  EXPECT_NE(modify_group(&group).code(), Code::OK);
  // try to delete a group id which does not exist
  EXPECT_NE(delete_group(&group).code(), Code::OK);
}

TEST_F(ActionProfTest, AddBadMemberIdToGroup) {
  DeviceMgr::Status status;
  uint32_t group_id = 1000;
  uint32_t bad_member_id = 123;
  auto group = make_group(group_id);
  add_member_to_group(&group, bad_member_id);
  EXPECT_CALL(*mock, action_prof_group_create(_, _, _));
  EXPECT_CALL(*mock, action_prof_group_add_member(_, _, _)).Times(0);
  EXPECT_NE(create_group(&group).code(), Code::OK);
}


class MatchTableIndirectTest : public DeviceMgrTest {
 protected:
  void set_action(p4::Action *action, const std::string &param_v) {
    auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    param->set_value(param_v);
  }

  p4::ActionProfileMember make_member(uint32_t member_id,
                                      const std::string &param_v = "") {
    p4::ActionProfileMember member;
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    member.set_action_profile_id(act_prof_id);
    member.set_member_id(member_id);
    set_action(member.mutable_action(), param_v);
    return member;
  }

  void create_member(uint32_t member_id, const std::string &param_v) {
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _));
    auto member = make_member(member_id, param_v);
    p4::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4::Update_Type_INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_member(&member);
    auto status = mgr.write(request);
    entity->release_action_profile_member();
    EXPECT_EQ(status.code(), Code::OK);
  }

  template <typename It>
  p4::ActionProfileGroup make_group(uint32_t group_id,
                                    It members_begin, It members_end) {
    p4::ActionProfileGroup group;
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    group.set_action_profile_id(act_prof_id);
    group.set_group_id(group_id);
    for (auto it = members_begin; it != members_end; ++it) {
      auto member = group.add_members();
      member->set_member_id(*it);
    }
    return group;
  }

  // create a group which includes the provided members
  template <typename It>
  void create_group(uint32_t group_id, It members_begin, It members_end) {
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _));
    EXPECT_CALL(*mock, action_prof_group_add_member(act_prof_id, _, _))
        .Times(std::distance(members_begin, members_end));
    auto group = make_group(group_id, members_begin, members_end);
    p4::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4::Update_Type_INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_group(&group);
    auto status = mgr.write(request);
    entity->release_action_profile_group();
    EXPECT_EQ(status.code(), Code::OK);
  }

  void create_group(uint32_t group_id, uint32_t member_id) {
    create_group(group_id, &member_id, (&member_id) + 1);
  }

  p4::TableEntry make_indirect_entry_to_member(const std::string &mf_v,
                                               uint32_t member_id) {
    return make_indirect_entry_common(mf_v, member_id, false);
  }

  p4::TableEntry make_indirect_entry_to_group(const std::string &mf_v,
                                               uint32_t group_id) {
    return make_indirect_entry_common(mf_v, group_id, true);
  }

  DeviceMgr::Status add_indirect_entry(p4::TableEntry *entry) {
    p4::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4::Update_Type_INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_table_entry(entry);
    auto status = mgr.write(request);
    entity->release_table_entry();
    return status;
  }

 private:
  p4::TableEntry make_indirect_entry_common(const std::string &mf_v,
                                            uint32_t indirect_id,
                                            bool is_group) {
    p4::TableEntry table_entry;
    auto t_id = pi_p4info_table_id_from_name(p4info, "IndirectWS");
    table_entry.set_table_id(t_id);
    auto mf = table_entry.add_match();
    mf->set_field_id(pi_p4info_table_match_field_id_from_name(
        p4info, t_id, "header_test.field32"));
    auto mf_exact = mf->mutable_exact();
    mf_exact->set_value(mf_v);
    auto entry = table_entry.mutable_action();
    if (is_group)
      entry->set_action_profile_group_id(indirect_id);
    else
      entry->set_action_profile_member_id(indirect_id);
    return table_entry;
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
  auto entry = make_indirect_entry_to_member(mf, member_id);
  auto status = add_indirect_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  p4::ReadResponse response;
  p4::Entity entity;
  auto table_entry = entity.mutable_table_entry();
  table_entry->set_table_id(t_id);
  status = mgr.read_one(entity, &response);
  ASSERT_EQ(status.code(), Code::OK);
  const auto &entities = response.entities();
  ASSERT_EQ(1, entities.size());
  ASSERT_TRUE(MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
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
  auto entry = make_indirect_entry_to_group(mf, group_id);
  auto status = add_indirect_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  p4::ReadResponse response;
  p4::Entity entity;
  auto table_entry = entity.mutable_table_entry();
  table_entry->set_table_id(t_id);
  status = mgr.read_one(entity, &response);
  ASSERT_EQ(status.code(), Code::OK);
  const auto &entities = response.entities();
  ASSERT_EQ(1, entities.size());
  ASSERT_TRUE(MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
