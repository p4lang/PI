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

#include <boost/optional.hpp>

#include <gmock/gmock.h>

#include <google/protobuf/util/message_differencer.h>

#include <fstream>  // std::ifstream
#include <iterator>  // std::distance
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <cstring>  // std::memcmp

#include "PI/frontends/proto/device_mgr.h"
#include "PI/int/pi_int.h"
#include "PI/pi.h"
#include "PI/proto/util.h"

#include "p4info_to_and_from_proto.h"

#include "google/rpc/code.pb.h"

#include "mock_switch.h"

namespace pi {
namespace proto {
namespace testing {
namespace {

using pi::fe::proto::DeviceMgr;
using Code = ::google::rpc::Code;

using google::protobuf::util::MessageDifferencer;

using ::testing::_;
using ::testing::Truly;
using ::testing::Pointee;
using ::testing::AtLeast;

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
    // releasing resource before the assert to avoid double free in case the
    // assert is false
    config.release_p4info();
    ASSERT_EQ(status.code(), Code::OK);
  }

  void TearDown() override { }

  DeviceMgr::Status add_entry(p4::TableEntry *entry) {
    p4::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4::Update_Type_INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_table_entry(entry);
    auto status = mgr.write(request);
    entity->release_table_entry();
    return status;
  }

  static constexpr const char *input_path = TESTDATADIR "/" "unittest.json";
  static pi_p4info_t *p4info;
  static p4::config::P4Info p4info_proto;
  static constexpr const char *invalid_p4_id_error_str = "Invalid P4 id";

  DummySwitchWrapper wrapper{};
  DummySwitchMock *mock;
  device_id_t device_id;
  DeviceMgr mgr;
};

pi_p4info_t *DeviceMgrTest::p4info = nullptr;
p4::config::P4Info DeviceMgrTest::p4info_proto;
constexpr const char *DeviceMgrTest::invalid_p4_id_error_str;

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

TEST_F(DeviceMgrTest, PipelineConfigGet) {
  p4::ForwardingPipelineConfig config;
  auto status = mgr.pipeline_config_get(&config);
  ASSERT_EQ(status.code(), Code::OK);
  EXPECT_TRUE(MessageDifferencer::Equals(p4info_proto, config.p4info()));
}

using ::testing::WithParamInterface;
using ::testing::Values;
using ::testing::Combine;

class MatchKeyInput {
 public:
  enum class Type {
    EXACT, LPM, TERNARY, RANGE
  };

  static MatchKeyInput make_exact(const std::string &mf_v) {
    return MatchKeyInput(Type::EXACT, mf_v, "", 0, 0);
  }

  static MatchKeyInput make_lpm(const std::string &mf_v, unsigned int pLen) {
    return MatchKeyInput(Type::LPM, mf_v, "", pLen, 0);
  }

  static MatchKeyInput make_ternary(const std::string &mf_v,
                                    const std::string &mask_v,
                                    int priority) {
    return MatchKeyInput(Type::TERNARY, mf_v, mask_v, 0, priority);
  }

  static MatchKeyInput make_range(const std::string &start_v,
                                  const std::string &end_v,
                                  int priority) {
    return MatchKeyInput(Type::RANGE, start_v, end_v, 0, priority);
  }

  Type get_type() const {
    return type;
  }

  std::string get_match_key() const {
    std::string mk(mf);
    mk += mask;
    if (type == Type::LPM) {
      std::string pLen_str(4, '\x00');
      pLen_str[0] = static_cast<char>(pLen);
      mk += pLen_str;
    }
    return mk;
  }

  p4::FieldMatch get_proto(pi_p4_id_t f_id) const {
    p4::FieldMatch fm;
    fm.set_field_id(f_id);
    switch (type) {
      case Type::EXACT:
        {
          auto exact = fm.mutable_exact();
          exact->set_value(mf);
          break;
        }
      case Type::LPM:
        {
          auto lpm = fm.mutable_lpm();
          lpm->set_value(mf);
          lpm->set_prefix_len(pLen);
          break;
        }
      case Type::TERNARY:
        {
          auto ternary = fm.mutable_ternary();
          ternary->set_value(mf);
          ternary->set_mask(mask);
          break;
        }
      case Type::RANGE:
        {
          auto range = fm.mutable_range();
          range->set_low(mf);
          range->set_high(mask);
          break;
        }
    }
    return fm;
  }

  int get_priority() const { return priority; }

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
  MatchKeyInput(Type type, const std::string &mf_v, const std::string &mask_v,
                unsigned int pLen, int pri)
      : type(type), mf(mf_v), mask(mask_v), pLen(pLen), priority(pri) { }

  Type type;
  std::string mf;
  std::string mask;
  unsigned int pLen;
  int priority;
};

class MatchTableTest
    : public DeviceMgrTest,
      public WithParamInterface<std::tuple<const char *, MatchKeyInput> > {
 protected:
  MatchTableTest() {
    t_id = pi_p4info_table_id_from_name(p4info, std::get<0>(GetParam()));
    mf_id = pi_p4info_table_match_field_id_from_name(
        p4info, t_id, "header_test.field32");
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  }

  p4::TableEntry generic_make(pi_p4_id_t t_id,
                              boost::optional<p4::FieldMatch> mf,
                              const std::string &param_v,
                              int priority = 0,
                              uint64_t controller_metadata = 0);

  DeviceMgr::Status generic_write(p4::Update_Type type, p4::TableEntry *entry);
  DeviceMgr::Status add_one(p4::TableEntry *entry);
  DeviceMgr::Status remove(p4::TableEntry *entry);
  DeviceMgr::Status modify(p4::TableEntry *entry);

  boost::optional<MatchKeyInput> default_mf() const;

  pi_p4_id_t t_id;
  pi_p4_id_t mf_id;
  pi_p4_id_t a_id;
};

DeviceMgr::Status
MatchTableTest::generic_write(p4::Update_Type type, p4::TableEntry *entry) {
  p4::WriteRequest request;
  auto update = request.add_updates();
  update->set_type(type);
  auto entity = update->mutable_entity();
  entity->set_allocated_table_entry(entry);
  auto status = mgr.write(request);
  entity->release_table_entry();
  return status;
}

DeviceMgr::Status
MatchTableTest::add_one(p4::TableEntry *entry) {
  return generic_write(p4::Update_Type_INSERT, entry);
}

DeviceMgr::Status
MatchTableTest::remove(p4::TableEntry *entry) {
  return generic_write(p4::Update_Type_DELETE, entry);
}

DeviceMgr::Status
MatchTableTest::modify(p4::TableEntry *entry) {
  return generic_write(p4::Update_Type_MODIFY, entry);
}

p4::TableEntry
MatchTableTest::generic_make(pi_p4_id_t t_id,
                             boost::optional<p4::FieldMatch> mf,
                             const std::string &param_v,
                             int priority,
                             uint64_t controller_metadata) {
  p4::TableEntry table_entry;
  table_entry.set_table_id(t_id);
  table_entry.set_controller_metadata(controller_metadata);
  table_entry.set_priority(priority);
  // not supported by older versions of boost
  // if (mf != boost::none) {
  if (mf.is_initialized()) {
    auto mf_ptr = table_entry.add_match();
    *mf_ptr = mf.get();
  }
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

boost::optional<MatchKeyInput>
MatchTableTest::default_mf() const {
  auto mk_input = std::get<1>(GetParam());
  switch (mk_input.get_type()) {
    case MatchKeyInput::Type::EXACT:
      return boost::none;
    case MatchKeyInput::Type::LPM:
      return MatchKeyInput::make_lpm(std::string(4, '\x00'), 0);
    case MatchKeyInput::Type::TERNARY:
      return MatchKeyInput::make_ternary(
          std::string(4, '\x00'), std::string(4, '\x00'), 0);
    case MatchKeyInput::Type::RANGE:
      return MatchKeyInput::make_range(
          std::string(4, '\x00'), std::string(4, '\xff'), 0);
  }
  return boost::none;  // unreachable
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
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mk_input.get_match_key()));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _))
      .Times(2);
  DeviceMgr::Status status;
  uint64_t controller_metadata(0xab);
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata,
                            mk_input.get_priority(), controller_metadata);
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

TEST_P(MatchTableTest, AddAndDelete) {
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mk_input.get_match_key()));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  DeviceMgr::Status status;
  auto entry = generic_make(
      t_id, mk_input.get_proto(mf_id), adata, mk_input.get_priority());
  status = add_one(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entry_delete_wkey(t_id, mk_matcher)).Times(2);
  status = remove(&entry);
  EXPECT_EQ(status.code(), Code::OK);
  // second call is error because match key has been removed already
  status = remove(&entry);
  EXPECT_NE(status.code(), Code::OK);
}

TEST_P(MatchTableTest, AddAndModify) {
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mk_input.get_match_key()));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  DeviceMgr::Status status;
  auto entry = generic_make(
      t_id, mk_input.get_proto(mf_id), adata, mk_input.get_priority());
  status = add_one(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  std::string new_adata(6, '\xaa');
  auto new_entry_matcher = Truly(TableEntryMatcher_Direct(a_id, new_adata));
  auto new_entry = generic_make(
      t_id, mk_input.get_proto(mf_id), adata, mk_input.get_priority());
  EXPECT_CALL(*mock, table_entry_modify_wkey(t_id, mk_matcher, entry_matcher));
  status = modify(&new_entry);
  EXPECT_EQ(status.code(), Code::OK);
}

TEST_P(MatchTableTest, SetDefault) {
  std::string adata(6, '\x00');
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_default_action_set(t_id, entry_matcher));
  auto entry = generic_make(t_id, boost::none, adata);
  entry.set_is_default_action(true);
  auto status = add_one(&entry);
  ASSERT_EQ(status.code(), Code::OK);
}

TEST_P(MatchTableTest, InvalidSetDefault) {
  // Invalid to set is_default_action flag to true with a non-empty match key
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata);
  entry.set_is_default_action(true);
  auto status = add_one(&entry);
  ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
}

TEST_P(MatchTableTest, InvalidTableId) {
  // build valid table entry, then modify the table id
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata);
  auto check_bad_status_write = [this, &entry](pi_p4_id_t bad_id) {
    entry.set_table_id(bad_id);
    auto status = add_one(&entry);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
    EXPECT_EQ(status.message(), invalid_p4_id_error_str);
  };
  auto check_bad_status_read = [this](pi_p4_id_t bad_id) {
    p4::ReadResponse response;
    p4::Entity entity;
    auto table_entry = entity.mutable_table_entry();
    table_entry->set_table_id(bad_id);
    auto status = mgr.read_one(entity, &response);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
    EXPECT_EQ(status.message(), invalid_p4_id_error_str);
  };
  // 0, aka missing id
  check_bad_status_write(0);
  // correct resource type id, bad index
  {
    auto bad_id = pi_make_table_id(0);
    while (pi_p4info_is_valid_id(p4info, bad_id)) bad_id++;
    check_bad_status_write(bad_id);
    check_bad_status_read(bad_id);
  }
  // invalid resource type id
  {
    auto bad_id = static_cast<pi_p4_id_t>(0xff << 24);
    check_bad_status_write(bad_id);
    check_bad_status_read(bad_id);
  }
}

TEST_P(MatchTableTest, InvalidActionId) {
  // build valid table entry, then modify the action id
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata);
  auto check_bad_status_write = [this, &entry](
      pi_p4_id_t bad_id, const char *msg = invalid_p4_id_error_str) {
    auto action = entry.mutable_action()->mutable_action();
    action->set_action_id(bad_id);
    auto status = add_one(&entry);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
    EXPECT_EQ(status.message(), msg);
  };
  // 0, aka missing id
  check_bad_status_write(0);
  // correct resource type id, bad index
  {
    auto bad_id = pi_make_action_id(0);
    while (pi_p4info_is_valid_id(p4info, bad_id)) bad_id++;
    check_bad_status_write(bad_id);
  }
  // invalid resource type id
  {
    auto bad_id = static_cast<pi_p4_id_t>(0xff << 24);
    check_bad_status_write(bad_id);
  }
  {
    auto bad_id = pi_p4info_action_id_from_name(p4info, "actionC");
    check_bad_status_write(bad_id, "Invalid action for table");
  }
}

TEST_P(MatchTableTest, MissingMatchField) {
  std::string adata(6, '\x00');
  auto mk_input = default_mf();
  if (mk_input.is_initialized()) {  // omitting field supported for match type
    auto mk_matcher = Truly(MatchKeyMatcher(
        t_id, mk_input.get().get_match_key()));
    auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
    EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
    auto entry = generic_make(t_id, boost::none, adata);
    auto status = add_one(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  } else {  // omitting field not supported for match type
    auto entry = generic_make(t_id, boost::none, adata);
    auto status = add_one(&entry);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
  }
}

#define MK std::string("\xaa\xbb\xcc\xdd", 4)
#define MASK std::string("\xff\x01\xf0\x0f", 4)
#define PREF_LEN 12
#define PRIORITY 77

INSTANTIATE_TEST_CASE_P(
    MatchTableTypes, MatchTableTest,
    Values(std::make_tuple("ExactOne", MatchKeyInput::make_exact(MK)),
           std::make_tuple("LpmOne", MatchKeyInput::make_lpm(MK, PREF_LEN)),
           std::make_tuple("TernaryOne",
                           MatchKeyInput::make_ternary(MK, MASK, PRIORITY)),
           std::make_tuple("RangeOne",
                           MatchKeyInput::make_range(MK, MASK, PRIORITY))));

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

  DeviceMgr::Status write_member(p4::Update_Type type,
                                 p4::ActionProfileMember *member) {
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

  DeviceMgr::Status write_group(p4::Update_Type type,
                                p4::ActionProfileGroup *group) {
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

TEST_F(ActionProfTest, InvalidActionProfId) {
  DeviceMgr::Status status;
  uint32_t member_id = 123;
  std::string adata(6, '\x00');
  auto member = make_member(member_id, adata);
  auto check_bad_status_write = [this, &member](pi_p4_id_t bad_id) {
    member.set_action_profile_id(bad_id);
    auto status = create_member(&member);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
    EXPECT_EQ(status.message(), invalid_p4_id_error_str);
  };
  auto check_bad_status_read = [this](pi_p4_id_t bad_id) {
    p4::ReadResponse response;
    p4::Entity entity;
    auto member = entity.mutable_action_profile_member();
    member->set_action_profile_id(bad_id);
    auto status = mgr.read_one(entity, &response);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
    EXPECT_EQ(status.message(), invalid_p4_id_error_str);
  };
  // 0, aka missing id
  check_bad_status_write(0);
  // correct resource type id, bad index
  {
    auto bad_id = pi_make_act_prof_id(0);
    while (pi_p4info_is_valid_id(p4info, bad_id)) bad_id++;
    check_bad_status_write(bad_id);
    check_bad_status_read(bad_id);
  }
  // invalid resource type id
  {
    auto bad_id = static_cast<pi_p4_id_t>(0xff << 24);
    check_bad_status_write(bad_id);
    check_bad_status_read(bad_id);
  }
}

TEST_F(ActionProfTest, InvalidActionId) {
  DeviceMgr::Status status;
  uint32_t member_id = 123;
  std::string adata(6, '\x00');
  auto member = make_member(member_id, adata);
  auto check_bad_status_write = [this, &member](
      pi_p4_id_t bad_id, const char *msg = invalid_p4_id_error_str) {
    auto action = member.mutable_action();
    action->set_action_id(bad_id);
    auto status = create_member(&member);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
    EXPECT_EQ(status.message(), msg);
  };
  check_bad_status_write(0);
  // correct resource type id, bad index
  {
    auto bad_id = pi_make_action_id(0);
    while (pi_p4info_is_valid_id(p4info, bad_id)) bad_id++;
    check_bad_status_write(bad_id);
  }
  // invalid resource type id
  {
    auto bad_id = static_cast<pi_p4_id_t>(0xff << 24);
    check_bad_status_write(bad_id);
  }
  {
    auto bad_id = pi_p4info_action_id_from_name(p4info, "actionC");
    check_bad_status_write(bad_id, "Invalid action for action profile");
  }
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
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
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
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
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


class ExactOneTest : public DeviceMgrTest {
 protected:
  ExactOneTest(const std::string &t_name, const std::string &f_name)
      : f_name(f_name) {
    t_id = pi_p4info_table_id_from_name(p4info, t_name.c_str());
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  }

  p4::TableEntry make_entry(const std::string &mf_v,
                            const std::string &param_v) {
    p4::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    auto mf = table_entry.add_match();
    mf->set_field_id(pi_p4info_table_match_field_id_from_name(
        p4info, t_id, f_name.c_str()));
    auto mf_exact = mf->mutable_exact();
    mf_exact->set_value(mf_v);
    auto entry = table_entry.mutable_action();
    auto action = entry->mutable_action();

    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    param->set_value(param_v);
    return table_entry;
  }

  const std::string f_name;
  pi_p4_id_t t_id;
  pi_p4_id_t a_id;
};


class DirectMeterTest : public ExactOneTest {
 protected:
  DirectMeterTest()
      : ExactOneTest("ExactOne", "header_test.field32") {
    m_id = pi_p4info_meter_id_from_name(p4info, "ExactOne_meter");
  }

  DeviceMgr::Status set_meter(p4::DirectMeterEntry *direct_meter_entry) {
    p4::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4::Update_Type_MODIFY);
    auto entity = update->mutable_entity();
    entity->set_allocated_direct_meter_entry(direct_meter_entry);
    auto status = mgr.write(request);
    entity->release_direct_meter_entry();
    return status;
  }

  p4::DirectMeterEntry make_meter_entry(const p4::TableEntry &entry,
                                        const p4::MeterConfig &config) {
    p4::DirectMeterEntry direct_meter_entry;
    direct_meter_entry.set_meter_id(m_id);
    direct_meter_entry.mutable_table_entry()->CopyFrom(entry);
    direct_meter_entry.mutable_config()->CopyFrom(config);
    return direct_meter_entry;
  }

  p4::MeterConfig make_meter_config() const {
    p4::MeterConfig config;
    config.set_cir(10);
    config.set_cburst(5);
    config.set_pir(100);
    config.set_pburst(250);
    return config;
  }

  pi_p4_id_t m_id;
};

struct MeterSpecMatcher {
 public:
  MeterSpecMatcher(const p4::MeterConfig &config,
                   pi_meter_unit_t meter_unit, pi_meter_type_t meter_type)
      : config(config), meter_unit(meter_unit), meter_type(meter_type) { }

  bool operator()(const pi_meter_spec_t *spec) const {
    return (spec->cir == static_cast<uint64_t>(config.cir()))
        && (spec->cburst == static_cast<uint32_t>(config.cburst()))
        && (spec->pir == static_cast<uint64_t>(config.pir()))
        && (spec->pburst == static_cast<uint32_t>(config.pburst()))
        && (spec->meter_unit == meter_unit)
        && (spec->meter_type == meter_type);
  }

 private:
  p4::MeterConfig config;
  pi_meter_unit_t meter_unit;
  pi_meter_type_t meter_type;
};

TEST_F(DirectMeterTest, Write) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mf));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  {
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  auto entry_h = mock->get_table_entry_handle();

  auto config = make_meter_config();
  auto meter_entry = make_meter_entry(entry, config);
  // as per the P4 program
  auto meter_spec_matcher = Truly(MeterSpecMatcher(
      config, PI_METER_UNIT_BYTES, PI_METER_TYPE_COLOR_UNAWARE));
  EXPECT_CALL(*mock, meter_set_direct(m_id, entry_h, meter_spec_matcher));
  {
    auto status = set_meter(&meter_entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
}

// TODO(antonin)
TEST_F(DirectMeterTest, WriteInTableEntry) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto meter_config = entry.mutable_meter_config();
  (void) meter_config;
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::UNIMPLEMENTED);
}

TEST_F(DirectMeterTest, InvalidTableEntry) {
  std::string adata(6, '\x00');
  std::string mf_1("\xaa\xbb\xcc\xdd", 4);
  auto entry_1 = make_entry(mf_1, adata);
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
  {
    auto status = add_entry(&entry_1);
    ASSERT_EQ(status.code(), Code::OK);
  }

  std::string mf_2("\xaa\xbb\xcc\xee", 4);
  auto entry_2 = make_entry(mf_2, adata);
  auto config = make_meter_config();
  auto meter_entry = make_meter_entry(entry_2, config);
  {
    auto status = set_meter(&meter_entry);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
  }
}

TEST_F(DirectMeterTest, InvalidMeterId) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto config = make_meter_config();
  auto meter_entry = make_meter_entry(entry, config);
  auto check_bad_status_write = [this, &meter_entry](pi_p4_id_t bad_id) {
    meter_entry.set_meter_id(bad_id);
    auto status = set_meter(&meter_entry);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
    EXPECT_EQ(status.message(), invalid_p4_id_error_str);
  };
  // 0, aka missing id
  check_bad_status_write(0);
  // correct resource type id, bad index
  {
    auto bad_id = pi_make_meter_id(0);
    while (pi_p4info_is_valid_id(p4info, bad_id)) bad_id++;
    check_bad_status_write(bad_id);
  }
  // invalid resource type id
  {
    auto bad_id = static_cast<pi_p4_id_t>(0xff << 24);
    check_bad_status_write(bad_id);
  }
}


class DirectCounterTest : public ExactOneTest {
 protected:
  DirectCounterTest()
      : ExactOneTest("ExactOne", "header_test.field32") {
    c_id = pi_p4info_counter_id_from_name(p4info, "ExactOne_counter");
  }

  // sends a read request for a DirectCounterEntry; returns the RPC status;
  // ignores the returned counter value(s)
  DeviceMgr::Status read_counter(p4::DirectCounterEntry *direct_counter_entry) {
    p4::ReadRequest request;
    p4::ReadResponse response;
    auto entity = request.add_entities();
    entity->set_allocated_direct_counter_entry(direct_counter_entry);
    auto status = mgr.read(request, &response);
    entity->release_direct_counter_entry();
    return status;
  }

  p4::DirectCounterEntry make_counter_entry(const p4::TableEntry *entry) {
    p4::DirectCounterEntry direct_counter_entry;
    direct_counter_entry.set_counter_id(c_id);
    if (entry) direct_counter_entry.mutable_table_entry()->CopyFrom(*entry);
    return direct_counter_entry;
  }

  pi_p4_id_t c_id;
};

TEST_F(DirectCounterTest, Read) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mf));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  {
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  auto entry_h = mock->get_table_entry_handle();

  auto counter_entry = make_counter_entry(&entry);
  EXPECT_CALL(*mock, counter_read_direct(c_id, entry_h, _, _));
  {
    auto status = read_counter(&counter_entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
}

TEST_F(DirectCounterTest, InvalidRequestReadAllFromDefault) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mf));
  auto entry_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  {
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }

  // default counter id + non-default table entry is invalid
  p4::DirectCounterEntry counter_entry;
  counter_entry.mutable_table_entry()->CopyFrom(entry);
  {
    auto status = read_counter(&counter_entry);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
  }
}

// TODO(antonin)
TEST_F(DirectCounterTest, ReadAllFromTable) {
  auto counter_entry = make_counter_entry(nullptr);  // default TableEntry
  auto status = read_counter(&counter_entry);
  ASSERT_EQ(status.code(), Code::UNIMPLEMENTED);
}

// TODO(antonin)
TEST_F(DirectCounterTest, ReadAll) {
  p4::DirectCounterEntry counter_entry;
  auto status = read_counter(&counter_entry);
  ASSERT_EQ(status.code(), Code::UNIMPLEMENTED);
}

// TODO(antonin)
TEST_F(DirectCounterTest, WriteInTableEntry) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto counter_data = entry.mutable_counter_data();
  (void) counter_data;
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::UNIMPLEMENTED);
}

class IndirectCounterTest : public DeviceMgrTest  {
 protected:
  IndirectCounterTest() {
    c_id = pi_p4info_counter_id_from_name(p4info, "CounterA");
    c_size = pi_p4info_counter_get_size(p4info, c_id);
  }

  pi_p4_id_t c_id{0};
  size_t c_size{0};
};

TEST_F(IndirectCounterTest, Read) {
  int index = 66;
  p4::ReadRequest request;
  p4::ReadResponse response;
  auto entity = request.add_entities();
  auto counter_entry = entity->mutable_counter_entry();
  counter_entry->set_counter_id(c_id);
  counter_entry->set_index(index);

  EXPECT_CALL(*mock, counter_read(c_id, index, _, _));
  auto status = mgr.read(request, &response);
  ASSERT_EQ(status.code(), Code::OK);
  const auto &entities = response.entities();
  ASSERT_EQ(1, entities.size());
  auto counter_data = counter_entry->mutable_data();
  counter_data->set_byte_count(0);
  counter_data->set_packet_count(0);
  ASSERT_TRUE(MessageDifferencer::Equals(*counter_entry,
                                         entities.Get(0).counter_entry()));
}

TEST_F(IndirectCounterTest, ReadAll) {
  p4::ReadRequest request;
  p4::ReadResponse response;
  auto entity = request.add_entities();
  auto counter_entry = entity->mutable_counter_entry();
  counter_entry->set_counter_id(c_id);

  // TODO(antonin): match index?
  EXPECT_CALL(*mock, counter_read(c_id, _, _, _)).Times(c_size);
  auto status = mgr.read(request, &response);
  ASSERT_EQ(status.code(), Code::OK);
  const auto &entities = response.entities();
  ASSERT_EQ(c_size, static_cast<size_t>(entities.size()));
  auto counter_data = counter_entry->mutable_data();
  counter_data->set_byte_count(0);
  counter_data->set_packet_count(0);
  for (size_t i = 0; i < c_size; i++) {
    const auto &entry = entities.Get(i).counter_entry();
    counter_entry->set_index(i);
    ASSERT_TRUE(MessageDifferencer::Equals(*counter_entry, entry));
  }
}


// Only testing for exact match tables for now, there is not much code variation
// between different table types.
class MatchKeyFormatTest : public ExactOneTest {
 protected:
  MatchKeyFormatTest()
      : ExactOneTest("ExactOneNonAligned", "header_test.field12") { }

  p4::TableEntry make_entry_no_mk() {
    p4::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    auto entry = table_entry.mutable_action();
    auto action = entry->mutable_action();

    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    std::string adata(6, '\x00');
    param->set_value(adata);
    return table_entry;
  }

  void add_one_mf(p4::TableEntry *entry, const std::string &mf_v) {
    auto mf = entry->add_match();
    mf->set_field_id(pi_p4info_table_match_field_id_from_name(
        p4info, t_id, "header_test.field12"));
    auto mf_exact = mf->mutable_exact();
    mf_exact->set_value(mf_v);
  }
};

TEST_F(MatchKeyFormatTest, Good1) {
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
  auto entry = make_entry_no_mk();
  std::string mf_v("\x0f\xbb", 2);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);
}

TEST_F(MatchKeyFormatTest, Good2) {
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
  auto entry = make_entry_no_mk();
  std::string mf_v("\x00\x00", 2);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);
}

TEST_F(MatchKeyFormatTest, MkMissingField) {
  auto entry = make_entry_no_mk();
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
}

TEST_F(MatchKeyFormatTest, MkTooLong) {
  auto entry = make_entry_no_mk();
  std::string mf_v("\x0a\xbb", 2);
  add_one_mf(&entry, mf_v);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
}

TEST_F(MatchKeyFormatTest, FieldTooShort) {
  auto entry = make_entry_no_mk();
  std::string mf_v("\x0a", 1);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
}

TEST_F(MatchKeyFormatTest, FieldTooLong) {
  auto entry = make_entry_no_mk();
  std::string mf_v("\xaa\xbb\xcc", 3);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
}

TEST_F(MatchKeyFormatTest, BadLeadingZeros) {
  auto entry = make_entry_no_mk();
  std::string mf_v("\x10\xbb", 2);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
}

class TernaryTwoTest : public DeviceMgrTest {
 protected:
  TernaryTwoTest() {
    t_id = pi_p4info_table_id_from_name(p4info, "TernaryTwo");
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  }

  p4::TableEntry make_entry(const std::string &mf1_v,
                            const std::string &mask1_v,
                            const std::string &mf2_v,
                            const std::string &mask2_v,
                            const std::string &param_v) {
    p4::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    if (!mf1_v.empty()) {
      auto mf = table_entry.add_match();
      mf->set_field_id(pi_p4info_table_match_field_id_from_name(
          p4info, t_id, "header_test.field32"));
      auto mf_ternary = mf->mutable_ternary();
      mf_ternary->set_value(mf1_v);
      mf_ternary->set_mask(mask1_v);
    }
    if (!mf2_v.empty()) {
      auto mf = table_entry.add_match();
      mf->set_field_id(pi_p4info_table_match_field_id_from_name(
          p4info, t_id, "header_test.field16"));
      auto mf_ternary = mf->mutable_ternary();
      mf_ternary->set_value(mf2_v);
      mf_ternary->set_mask(mask2_v);
    }
    auto entry = table_entry.mutable_action();
    auto action = entry->mutable_action();

    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    param->set_value(param_v);
    return table_entry;
  }

  std::string make_match_key(const std::string &mf1_v,
                             const std::string &mask1_v,
                             const std::string &mf2_v,
                             const std::string &mask2_v) {
    return mf1_v + mask1_v + mf2_v + mask2_v;
  }

  const std::string f_name;
  pi_p4_id_t t_id;
  pi_p4_id_t a_id;
};

// THIS IS NOT TRUE ANYMORE NOW THAT WE HAVE THE IS_DEFAULT_ACTION FLAG
// TODO(antonin): remove the test?
// This test is the reason why we need 2 match fields in the table. If the match
// key is empty, the semantics of P4Runtime are different: it means "set the
// default entry".
TEST_F(TernaryTwoTest, MissingMatchField) {
  const std::string mf1_v;
  const std::string mask1_v;
  const std::string mf2_v("\xaa\xbb", 2);
  const std::string mask2_v("\xff\xff", 2);
  const std::string param_v(6, '\x00');
  auto entry = make_entry(mf1_v, mask1_v, mf2_v, mask2_v, param_v);
  const std::string zeros(4, '\x00');
  auto mk = make_match_key(zeros, zeros, mf2_v, mask2_v);
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mk));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, _, _));
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
