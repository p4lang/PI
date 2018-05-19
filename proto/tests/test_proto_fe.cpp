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

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/message_differencer.h>

#include <atomic>
#include <fstream>  // std::ifstream
#include <iterator>  // std::distance
#include <memory>
#include <ostream>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include <cstring>  // std::memcmp

#include "PI/frontends/cpp/tables.h"
#include "PI/frontends/proto/device_mgr.h"
#include "PI/int/pi_int.h"
#include "PI/pi.h"
#include "PI/proto/util.h"

#include "p4info_to_and_from_proto.h"

#include "google/rpc/code.pb.h"

#include "matchers.h"
#include "mock_switch.h"

namespace p4rt = ::p4::v1;
namespace p4config = ::p4::config::v1;

// Needs to be in same namespace as google::rpc::Status for ADL
namespace google {
namespace rpc {
std::ostream &operator<<(std::ostream &out, const Status &status) {
  out << "Status(code=" << status.code() << ", message='" << status.message()
      << "', details=";
  for (const auto &error_any : status.details()) {
    p4rt::Error error;
    if (!error_any.UnpackTo(&error)) {
      out << "INVALID + ";
    } else {
      out << "Error(code=" << error.canonical_code() << ", message='"
          << error.message() << "') + ";
    }
  }
  out << ")";
  return out;
}
}  // namespace rpc
}  // namespace google

namespace pi {
namespace proto {
namespace testing {
namespace {

using pi::fe::proto::DeviceMgr;
using Code = ::google::rpc::Code;

using google::protobuf::util::MessageDifferencer;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;

// Used to make sure that a google::rpc::Status object has the correct format
// and contains a single p4rt::Error message with a matching canonical error
// code and message. The test writer can simply write the following:
// EXPECT_EQ(returned_status, OneExpectedError(expected_code [, expected_msg]));
struct OneExpectedError {
  OneExpectedError(Code code, const char *msg)
      : code(code), msg(msg) { }
  explicit OneExpectedError(Code code, const std::string msg = "")
      : code(code), msg(msg) { }

  friend std::ostream &operator<<(std::ostream &out,
                                  const OneExpectedError &error);

  Code code;
  std::string msg;
};

bool operator==(const DeviceMgr::Status &status,
                const OneExpectedError &expected) {
  if (status.code() != Code::UNKNOWN) return false;
  if (status.details().size() != 1) return false;
  const auto &error_any = status.details().Get(0);
  p4rt::Error error;
  if (!error_any.UnpackTo(&error)) return false;
  if (error.canonical_code() != expected.code) return false;
  if (!expected.msg.empty() && (expected.msg != error.message())) return false;
  return true;
}

// TODO(antonin): uncommenting this triggers an unused warning due to the
// anonymous namespace, since we have only been using the operator above
// bool operator==(const OneExpectedError &expected,
//                 const DeviceMgr::Status &status) {
//   return operator ==(status, expected);
// }

std::ostream &operator<<(std::ostream &out, const OneExpectedError &error) {
  out << "code=" << error.code;
  if (!error.msg.empty()) out << ", message='" << error.msg << "'";
  return out;
}

// Used to make sure that a google::rpc::Status object has the correct format
// and contains the correct error codes in the details field, which is a
// repeated field of p4rt::Error messages (as Any messages).
struct ExpectedErrors {
  void push_back(Code code) {
    expected_codes.push_back(code);
  }

  Code at(size_t i) const { return expected_codes.at(i); }

  size_t size() const { return expected_codes.size(); }

  friend std::ostream &operator<<(std::ostream &out,
                                  const ExpectedErrors &error);

  std::vector<Code> expected_codes;
};

bool operator==(const DeviceMgr::Status &status,
                const ExpectedErrors &expected_errors) {
  if (status.code() != Code::UNKNOWN) return false;
  if (static_cast<size_t>(status.details().size()) != expected_errors.size())
    return false;
  for (size_t i = 0; i < expected_errors.size(); i++) {
    const auto &error_any = status.details().Get(i);
    p4rt::Error error;
    if (!error_any.UnpackTo(&error)) return false;
    if (error.canonical_code() != expected_errors.at(i)) return false;
  }
  return true;
}

std::ostream &operator<<(std::ostream &out, const ExpectedErrors &errors) {
  out << "[";
  for (auto code : errors.expected_codes)
    out << "code=" << code << " + ";
  out << "]";
  return out;
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
    std::ifstream istream(input_path);
    google::protobuf::io::IstreamInputStream istream_(&istream);
    google::protobuf::TextFormat::Parse(&istream_, &p4info_proto);
    pi::p4info::p4info_proto_reader(p4info_proto, &p4info);
  }

  static void TearDownTestCase() {
    pi_destroy_config(p4info);
    DeviceMgr::destroy();
  }

  void SetUp() override {
    p4rt::ForwardingPipelineConfig config;
    config.set_allocated_p4info(&p4info_proto);
    auto status = mgr.pipeline_config_set(
        p4rt::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT,
        config);
    // releasing resource before the assert to avoid double free in case the
    // assert is false
    config.release_p4info();
    ASSERT_EQ(status.code(), Code::OK);
  }

  void TearDown() override { }

  DeviceMgr::Status add_entry(p4rt::TableEntry *entry) {
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_table_entry(entry);
    auto status = mgr.write(request);
    entity->release_table_entry();
    return status;
  }

  DeviceMgr::Status read_table_entries(pi_p4_id_t t_id,
                                       p4rt::ReadResponse *response) {
    p4rt::Entity entity;
    auto table_entry = entity.mutable_table_entry();
    table_entry->set_table_id(t_id);
    return mgr.read_one(entity, response);
  }

  DeviceMgr::Status read_table_entry(p4rt::TableEntry *table_entry,
                                     p4rt::ReadResponse *response) {
    p4rt::Entity entity;
    entity.set_allocated_table_entry(table_entry);
    auto status = mgr.read_one(entity, response);
    entity.release_table_entry();
    return status;
  }

  static constexpr const char *input_path =
           TESTDATADIR "/" "unittest.p4info.txt";
  static pi_p4info_t *p4info;
  static p4config::P4Info p4info_proto;
  static constexpr const char *invalid_p4_id_error_str = "Invalid P4 id";

  DummySwitchWrapper wrapper{};
  DummySwitchMock *mock;
  device_id_t device_id;
  DeviceMgr mgr;
};

pi_p4info_t *DeviceMgrTest::p4info = nullptr;
p4config::P4Info DeviceMgrTest::p4info_proto;
constexpr const char *DeviceMgrTest::invalid_p4_id_error_str;

TEST_F(DeviceMgrTest, ResourceTypeFromId) {
  using Type = p4config::P4Ids;
  using pi::proto::util::resource_type_from_id;
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  ASSERT_EQ(Type::ACTION, resource_type_from_id(a_id));
  auto t_id = pi_p4info_table_id_from_name(p4info, "ExactOne");
  ASSERT_EQ(Type::TABLE, resource_type_from_id(t_id));
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  ASSERT_EQ(Type::ACTION_PROFILE, resource_type_from_id(act_prof_id));
  auto dc_id = pi_p4info_counter_id_from_name(p4info, "ExactOne_counter");
  ASSERT_EQ(Type::DIRECT_COUNTER, resource_type_from_id(dc_id));
  auto dm_id = pi_p4info_meter_id_from_name(p4info, "ExactOne_meter");
  ASSERT_EQ(Type::DIRECT_METER, resource_type_from_id(dm_id));
  auto c_id = pi_p4info_counter_id_from_name(p4info, "CounterA");
  ASSERT_EQ(Type::COUNTER, resource_type_from_id(c_id));
  auto m_id = pi_p4info_meter_id_from_name(p4info, "MeterA");
  ASSERT_EQ(Type::METER, resource_type_from_id(m_id));
  ASSERT_EQ(Type::UNSPECIFIED,
            resource_type_from_id(pi::proto::util::invalid_id()));
}

TEST_F(DeviceMgrTest, PipelineConfigGet) {
  p4rt::ForwardingPipelineConfig config;
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

  p4rt::FieldMatch get_proto(pi_p4_id_t f_id) const {
    p4rt::FieldMatch fm;
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

  p4rt::TableEntry generic_make(pi_p4_id_t t_id,
                                boost::optional<p4rt::FieldMatch> mf,
                                const std::string &param_v,
                                int priority = 0,
                                uint64_t controller_metadata = 0);

  DeviceMgr::Status generic_write(p4rt::Update_Type type,
                                  p4rt::TableEntry *entry);
  DeviceMgr::Status add_one(p4rt::TableEntry *entry);
  DeviceMgr::Status remove(p4rt::TableEntry *entry);
  DeviceMgr::Status modify(p4rt::TableEntry *entry);

  boost::optional<MatchKeyInput> default_mf() const;

  pi_p4_id_t t_id;
  pi_p4_id_t mf_id;
  pi_p4_id_t a_id;
};

DeviceMgr::Status
MatchTableTest::generic_write(p4rt::Update_Type type, p4rt::TableEntry *entry) {
  p4rt::WriteRequest request;
  auto update = request.add_updates();
  update->set_type(type);
  auto entity = update->mutable_entity();
  entity->set_allocated_table_entry(entry);
  auto status = mgr.write(request);
  entity->release_table_entry();
  return status;
}

DeviceMgr::Status
MatchTableTest::add_one(p4rt::TableEntry *entry) {
  return generic_write(p4rt::Update_Type_INSERT, entry);
}

DeviceMgr::Status
MatchTableTest::remove(p4rt::TableEntry *entry) {
  return generic_write(p4rt::Update_Type_DELETE, entry);
}

DeviceMgr::Status
MatchTableTest::modify(p4rt::TableEntry *entry) {
  return generic_write(p4rt::Update_Type_MODIFY, entry);
}

p4rt::TableEntry
MatchTableTest::generic_make(pi_p4_id_t t_id,
                             boost::optional<p4rt::FieldMatch> mf,
                             const std::string &param_v,
                             int priority,
                             uint64_t controller_metadata) {
  p4rt::TableEntry table_entry;
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

TEST_P(MatchTableTest, AddAndRead) {
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto mk_matcher = CorrectMatchKey(t_id, mk_input.get_match_key());
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _))
      .Times(AtLeast(1));
  uint64_t controller_metadata(0xab);
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata,
                            mk_input.get_priority(), controller_metadata);
  {
    auto status = add_one(&entry);
    EXPECT_EQ(status.code(), Code::OK);
  }
  // second is error because duplicate match key
  {
    auto status = add_one(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::ALREADY_EXISTS));
  }

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _)).Times(2);
  // 2 different reads: first one is wildcard read on the table, other filters
  // on the match key.
  {
    p4rt::ReadResponse response;
    auto status = read_table_entries(t_id, &response);
    ASSERT_EQ(status.code(), Code::OK);
    const auto &entities = response.entities();
    ASSERT_EQ(1, entities.size());
    EXPECT_TRUE(
        MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
  }
  {
    p4rt::ReadResponse response;
    auto status = read_table_entry(&entry, &response);
    ASSERT_EQ(status.code(), Code::OK);
    const auto &entities = response.entities();
    ASSERT_EQ(1, entities.size());
    EXPECT_TRUE(
        MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
  }
}

TEST_P(MatchTableTest, AddAndDelete) {
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto mk_matcher = CorrectMatchKey(t_id, mk_input.get_match_key());
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  DeviceMgr::Status status;
  auto entry = generic_make(
      t_id, mk_input.get_proto(mf_id), adata, mk_input.get_priority());
  status = add_one(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entry_delete_wkey(t_id, mk_matcher))
      .Times(AtLeast(1));
  status = remove(&entry);
  EXPECT_EQ(status.code(), Code::OK);
  // second call is error because match key has been removed already
  status = remove(&entry);
  EXPECT_EQ(status, OneExpectedError(Code::NOT_FOUND));
}

TEST_P(MatchTableTest, AddAndModify) {
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto mk_matcher = CorrectMatchKey(t_id, mk_input.get_match_key());
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  DeviceMgr::Status status;
  auto entry = generic_make(
      t_id, mk_input.get_proto(mf_id), adata, mk_input.get_priority());
  status = add_one(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  std::string new_adata(6, '\xaa');
  auto new_entry_matcher = CorrectTableEntryDirect(a_id, new_adata);
  auto new_entry = generic_make(
      t_id, mk_input.get_proto(mf_id), adata, mk_input.get_priority());
  EXPECT_CALL(*mock, table_entry_modify_wkey(t_id, mk_matcher, entry_matcher));
  status = modify(&new_entry);
  EXPECT_EQ(status.code(), Code::OK);
}

TEST_P(MatchTableTest, SetDefault) {
  std::string adata(6, '\x00');
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_default_action_set(t_id, entry_matcher))
      .Times(AtLeast(1));
  auto entry = generic_make(t_id, boost::none, adata);
  entry.set_is_default_action(true);
  {
    auto status = add_one(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  // TODO(antonin): desired behavior?
  // {
  //   auto status = add_one(&entry);
  //   EXPECT_EQ(status, OneExpectedError(Code::ALREADY_EXISTS));
  // }

  EXPECT_CALL(*mock, table_default_action_reset(t_id))
      .Times(AtLeast(1));
  {
    auto status = remove(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  // TODO(antonin): desired behavior?
  // {
  //   auto status = remove(&entry);
  //   EXPECT_EQ(status, OneExpectedError(Code::NOT_FOUND));
  // }
}

TEST_P(MatchTableTest, InvalidSetDefault) {
  // Invalid to set is_default_action flag to true with a non-empty match key
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata);
  entry.set_is_default_action(true);
  auto status = add_one(&entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

TEST_P(MatchTableTest, InvalidTableId) {
  // build valid table entry, then modify the table id
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata);
  auto check_bad_status_write = [this, &entry](pi_p4_id_t bad_id) {
    entry.set_table_id(bad_id);
    auto status = add_one(&entry);
    EXPECT_EQ(
        status,
        OneExpectedError(Code::INVALID_ARGUMENT, invalid_p4_id_error_str));
  };
  auto check_bad_status_read = [this](pi_p4_id_t bad_id) {
    p4rt::ReadResponse response;
    p4rt::Entity entity;
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
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT, msg));
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
    auto mk_matcher = CorrectMatchKey(t_id, mk_input.get().get_match_key());
    auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
    auto entry = generic_make(t_id, boost::none, adata);
    auto status = add_one(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  } else {  // omitting field not supported for match type
    auto entry = generic_make(t_id, boost::none, adata);
    auto status = add_one(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
}

TEST_P(MatchTableTest, WriteBatchWithError) {
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto mk_matcher = CorrectMatchKey(t_id, mk_input.get_match_key());
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_entry_delete_wkey(t_id, mk_matcher))
      .Times(AnyNumber());
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _))
      .Times(AtLeast(1));
  auto entry = generic_make(
      t_id, mk_input.get_proto(mf_id), adata, mk_input.get_priority());

  ExpectedErrors expected_errors;
  p4rt::WriteRequest request;
  {
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_DELETE);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(entry);
    expected_errors.push_back(Code::NOT_FOUND);
  }
  {
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_INSERT);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(entry);
    expected_errors.push_back(Code::OK);
  }
  {
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_INSERT);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(entry);
    expected_errors.push_back(Code::ALREADY_EXISTS);
  }
  auto status = mgr.write(request);
  EXPECT_EQ(status, expected_errors);
}

#define MK std::string("\xaa\xbb\xcc\xdd", 4)
#define MASK std::string("\xff\x01\xf0\x0f", 4)
// for ternary, we need to ensure that mk == mk & mask
#define TERNARY_MK std::string("\xaa\x01\xc0\x0d", 4)
#define PREF_LEN 12
// for LPM, we need to ensure that mk ends with the appropriate number of
// trailing zeros
#define LPM_MK std::string("\xaa\xf0\x00\x00", 4)
#define PRIORITY 77

INSTANTIATE_TEST_CASE_P(
    MatchTableTypes, MatchTableTest,
    Values(std::make_tuple("ExactOne", MatchKeyInput::make_exact(MK)),
           std::make_tuple("LpmOne", MatchKeyInput::make_lpm(LPM_MK, PREF_LEN)),
           std::make_tuple(
               "TernaryOne",
               MatchKeyInput::make_ternary(TERNARY_MK, MASK, PRIORITY)),
           std::make_tuple("RangeOne",
                           MatchKeyInput::make_range(MK, MASK, PRIORITY))));

#undef MK
#undef MASK
#undef TERNARY_MK
#undef PREF_LEN
#undef LPM_MK


class ActionProfTest : public DeviceMgrTest {
 protected:
  void set_action(p4rt::Action *action, const std::string &param_v) {
    auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    param->set_value(param_v);
  }

  p4rt::ActionProfileMember make_member(uint32_t member_id,
                                        const std::string &param_v = "") {
    p4rt::ActionProfileMember member;
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    member.set_action_profile_id(act_prof_id);
    member.set_member_id(member_id);
    set_action(member.mutable_action(), param_v);
    return member;
  }

  DeviceMgr::Status write_member(p4rt::Update_Type type,
                                 p4rt::ActionProfileMember *member) {
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(type);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_member(member);
    auto status = mgr.write(request);
    entity->release_action_profile_member();
    return status;
  }

  DeviceMgr::Status create_member(p4rt::ActionProfileMember *member) {
    return write_member(p4rt::Update_Type_INSERT, member);
  }

  DeviceMgr::Status modify_member(p4rt::ActionProfileMember *member) {
    return write_member(p4rt::Update_Type_MODIFY, member);
  }

  DeviceMgr::Status delete_member(p4rt::ActionProfileMember *member) {
    return write_member(p4rt::Update_Type_DELETE, member);
  }

  void add_member_to_group(p4rt::ActionProfileGroup *group,
                           uint32_t member_id) {
    auto member = group->add_members();
    member->set_member_id(member_id);
  }

  template <typename It>
  p4rt::ActionProfileGroup make_group(uint32_t group_id,
                                      It members_begin, It members_end) {
    p4rt::ActionProfileGroup group;
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    group.set_action_profile_id(act_prof_id);
    group.set_group_id(group_id);
    for (auto it = members_begin; it != members_end; ++it) {
      auto member = group.add_members();
      member->set_member_id(*it);
    }
    return group;
  }

  p4rt::ActionProfileGroup make_group(uint32_t group_id) {
    std::vector<uint32_t> members;
    return make_group(group_id, members.begin(), members.end());
  }

  DeviceMgr::Status write_group(p4rt::Update_Type type,
                                p4rt::ActionProfileGroup *group) {
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(type);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_group(group);
    auto status = mgr.write(request);
    entity->release_action_profile_group();
    return status;
  }

  DeviceMgr::Status create_group(p4rt::ActionProfileGroup *group) {
    return write_group(p4rt::Update_Type_INSERT, group);
  }

  DeviceMgr::Status modify_group(p4rt::ActionProfileGroup *group) {
    return write_group(p4rt::Update_Type_MODIFY, group);
  }

  DeviceMgr::Status delete_group(p4rt::ActionProfileGroup *group) {
    return write_group(p4rt::Update_Type_DELETE, group);
  }
};

TEST_F(ActionProfTest, Member) {
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  uint32_t member_id_1 = 123, member_id_2 = 234;  // can be arbitrary
  std::string adata_1(6, '\x00');
  std::string adata_2(6, '\x11');
  auto ad_matcher_1 = CorrectActionData(a_id, adata_1);
  auto ad_matcher_2 = CorrectActionData(a_id, adata_2);

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
  p4rt::ReadResponse response;
  p4rt::ReadRequest request;
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
    EXPECT_EQ(
        status,
        OneExpectedError(Code::INVALID_ARGUMENT, invalid_p4_id_error_str));
  };
  auto check_bad_status_read = [this](pi_p4_id_t bad_id) {
    p4rt::ReadResponse response;
    p4rt::Entity entity;
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
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT, msg));
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
  void set_action(p4rt::Action *action, const std::string &param_v) {
    auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    param->set_value(param_v);
  }

  p4rt::ActionProfileMember make_member(uint32_t member_id,
                                        const std::string &param_v = "") {
    p4rt::ActionProfileMember member;
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
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_member(&member);
    auto status = mgr.write(request);
    entity->release_action_profile_member();
    EXPECT_EQ(status.code(), Code::OK);
  }

  template <typename It>
  p4rt::ActionProfileGroup make_group(uint32_t group_id,
                                      It members_begin, It members_end) {
    p4rt::ActionProfileGroup group;
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
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_group(&group);
    auto status = mgr.write(request);
    entity->release_action_profile_group();
    EXPECT_EQ(status.code(), Code::OK);
  }

  void create_group(uint32_t group_id, uint32_t member_id) {
    create_group(group_id, &member_id, (&member_id) + 1);
  }

  p4rt::TableEntry make_indirect_entry_to_member(const std::string &mf_v,
                                                 uint32_t member_id) {
    return make_indirect_entry_common(mf_v, member_id, false);
  }

  p4rt::TableEntry make_indirect_entry_to_group(const std::string &mf_v,
                                                uint32_t group_id) {
    return make_indirect_entry_common(mf_v, group_id, true);
  }

  DeviceMgr::Status add_indirect_entry(p4rt::TableEntry *entry) {
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_table_entry(entry);
    auto status = mgr.write(request);
    entity->release_table_entry();
    return status;
  }

 private:
  p4rt::TableEntry make_indirect_entry_common(const std::string &mf_v,
                                              uint32_t indirect_id,
                                              bool is_group) {
    p4rt::TableEntry table_entry;
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
  auto mk_matcher = CorrectMatchKey(t_id, mf);
  auto entry_matcher = CorrectTableEntryIndirect(mbr_h);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  auto entry = make_indirect_entry_to_member(mf, member_id);
  auto status = add_indirect_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  p4rt::ReadResponse response;
  p4rt::Entity entity;
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
  auto mk_matcher = CorrectMatchKey(t_id, mf);
  auto entry_matcher = CorrectTableEntryIndirect(grp_h);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  auto entry = make_indirect_entry_to_group(mf, group_id);
  auto status = add_indirect_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  p4rt::ReadResponse response;
  p4rt::Entity entity;
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

  ExactOneTest()
      : ExactOneTest("ExactOne", "header_test.field32") { }

  p4rt::TableEntry make_entry(const std::string &mf_v,
                              const std::string &param_v) {
    p4rt::TableEntry table_entry;
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

TEST_F(ExactOneTest, PriorityForNonTernaryMatch) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  int priority(789);
  auto entry = make_entry(mf, adata);
  entry.set_priority(priority);
  auto status = add_entry(&entry);
  ASSERT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}


class DirectMeterTest : public ExactOneTest {
 protected:
  DirectMeterTest()
      : ExactOneTest("ExactOne", "header_test.field32") {
    m_id = pi_p4info_meter_id_from_name(p4info, "ExactOne_meter");
  }

  DeviceMgr::Status set_meter(p4rt::DirectMeterEntry *direct_meter_entry) {
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_MODIFY);
    auto entity = update->mutable_entity();
    entity->set_allocated_direct_meter_entry(direct_meter_entry);
    auto status = mgr.write(request);
    entity->release_direct_meter_entry();
    return status;
  }

  p4rt::DirectMeterEntry make_meter_entry(const p4rt::TableEntry &entry,
                                          const p4rt::MeterConfig &config) {
    p4rt::DirectMeterEntry direct_meter_entry;
    direct_meter_entry.mutable_table_entry()->CopyFrom(entry);
    direct_meter_entry.mutable_config()->CopyFrom(config);
    return direct_meter_entry;
  }

  p4rt::MeterConfig make_meter_config() const {
    p4rt::MeterConfig config;
    config.set_cir(10);
    config.set_cburst(5);
    config.set_pir(100);
    config.set_pburst(250);
    return config;
  }

  DeviceMgr::Status read_meter(p4rt::DirectMeterEntry *direct_meter_entry,
                               p4rt::ReadResponse *response) {
    p4rt::ReadRequest request;
    auto entity = request.add_entities();
    entity->set_allocated_direct_meter_entry(direct_meter_entry);
    auto status = mgr.read(request, response);
    entity->release_direct_meter_entry();
    return status;
  }

  pi_p4_id_t m_id;
};

TEST_F(DirectMeterTest, WriteAndRead) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto mk_matcher = CorrectMatchKey(t_id, mf);
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  {
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  auto entry_h = mock->get_table_entry_handle();

  auto config = make_meter_config();
  auto meter_entry = make_meter_entry(entry, config);
  // as per the P4 program
  auto meter_spec_matcher = CorrectMeterSpec(
      config, PI_METER_UNIT_BYTES, PI_METER_TYPE_COLOR_UNAWARE);
  EXPECT_CALL(*mock, meter_set_direct(m_id, entry_h, meter_spec_matcher));
  {
    auto status = set_meter(&meter_entry);
    ASSERT_EQ(status.code(), Code::OK);
  }

  // read with DirectMeterEntry
  EXPECT_CALL(*mock, meter_read_direct(m_id, entry_h, _));
  {
    p4rt::ReadResponse response;
    auto status = read_meter(&meter_entry, &response);
    ASSERT_EQ(status.code(), Code::OK);
    const auto &entities = response.entities();
    ASSERT_EQ(1, entities.size());
    const auto &read_entry = entities.Get(0).direct_meter_entry();
    EXPECT_TRUE(MessageDifferencer::Equals(meter_entry, read_entry));
  }

  // read with TableEntry
  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  {
    p4rt::ReadResponse response;
    p4rt::Entity entity;
    auto table_entry = entity.mutable_table_entry();
    table_entry->set_table_id(t_id);
    table_entry->mutable_meter_config();
    auto status = mgr.read_one(entity, &response);

    ASSERT_EQ(status.code(), Code::OK);
    const auto &entities = response.entities();
    ASSERT_EQ(1, entities.size());
    const auto &read_entry = entities.Get(0).table_entry();
    EXPECT_TRUE(MessageDifferencer::Equals(config, read_entry.meter_config()));
  }
}

TEST_F(DirectMeterTest, WriteInTableEntry) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto *meter_config = entry.mutable_meter_config();
  *meter_config = make_meter_config();

  auto mk_matcher = CorrectMatchKey(t_id, mf);
  auto *entry_matcher_ = new TableEntryMatcher_Direct(a_id, adata);
  // expected meter spec as per the P4 program
  entry_matcher_->add_direct_meter(
      m_id, *meter_config, PI_METER_UNIT_BYTES, PI_METER_TYPE_COLOR_UNAWARE);
  auto entry_matcher = ::testing::MakeMatcher(entry_matcher_);

  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  auto status = add_entry(&entry);
  EXPECT_EQ(status.code(), Code::OK);
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
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
}

TEST_F(DirectMeterTest, MissingTableEntry) {
  p4rt::DirectMeterEntry meter_entry;
  auto status = set_meter(&meter_entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

class IndirectMeterTest : public DeviceMgrTest  {
 protected:
  IndirectMeterTest() {
    m_id = pi_p4info_meter_id_from_name(p4info, "MeterA");
    m_size = pi_p4info_meter_get_size(p4info, m_id);
  }

  DeviceMgr::Status read_meter(p4rt::MeterEntry *meter_entry,
                               p4rt::ReadResponse *response) {
    p4rt::ReadRequest request;
    auto entity = request.add_entities();
    entity->set_allocated_meter_entry(meter_entry);
    auto status = mgr.read(request, response);
    entity->release_meter_entry();
    return status;
  }

  DeviceMgr::Status write_meter(p4rt::MeterEntry *meter_entry) {
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_MODIFY);
    auto entity = update->mutable_entity();
    entity->set_allocated_meter_entry(meter_entry);
    auto status = mgr.write(request);
    entity->release_meter_entry();
    return status;
  }

  p4rt::MeterConfig make_meter_config() const {
    p4rt::MeterConfig config;
    config.set_cir(10);
    config.set_cburst(5);
    config.set_pir(100);
    config.set_pburst(250);
    return config;
  }

  void set_index(p4rt::MeterEntry *meter_entry, int index) const {
    auto *index_msg = meter_entry->mutable_index();
    index_msg->set_index(index);
  }

  pi_p4_id_t m_id{0};
  size_t m_size{0};
};

TEST_F(IndirectMeterTest, WriteAndRead) {
  int index = 66;
  p4rt::ReadResponse response;
  p4rt::MeterEntry meter_entry;
  meter_entry.set_meter_id(m_id);
  set_index(&meter_entry, index);
  auto meter_config = make_meter_config();
  meter_entry.mutable_config()->CopyFrom(meter_config);
  // meter type & unit as per the P4 program
  auto meter_matcher = CorrectMeterSpec(
      meter_config, PI_METER_UNIT_PACKETS, PI_METER_TYPE_COLOR_UNAWARE);
  EXPECT_CALL(*mock, meter_set(m_id, index, meter_matcher));
  {
    auto status = write_meter(&meter_entry);
    ASSERT_EQ(status.code(), Code::OK);
  }

  EXPECT_CALL(*mock, meter_read(m_id, index, _));
  {
    auto status = read_meter(&meter_entry, &response);
    ASSERT_EQ(status.code(), Code::OK);
  }
  const auto &entities = response.entities();
  ASSERT_EQ(1, entities.size());
  const auto &read_meter_entry = entities.Get(0).meter_entry();
  EXPECT_TRUE(MessageDifferencer::Equals(meter_entry, read_meter_entry));
}

class DirectCounterTest : public ExactOneTest {
 protected:
  DirectCounterTest()
      : ExactOneTest("ExactOne", "header_test.field32") {
    c_id = pi_p4info_counter_id_from_name(p4info, "ExactOne_counter");
  }

  // sends a read request for a DirectCounterEntry; returns the RPC status
  DeviceMgr::Status read_counter(p4rt::DirectCounterEntry *direct_counter_entry,
                                 p4rt::ReadResponse *response) {
    p4rt::ReadRequest request;
    auto entity = request.add_entities();
    entity->set_allocated_direct_counter_entry(direct_counter_entry);
    auto status = mgr.read(request, response);
    entity->release_direct_counter_entry();
    return status;
  }

  DeviceMgr::Status write_counter(
      p4rt::DirectCounterEntry *direct_counter_entry) {
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_MODIFY);
    auto entity = update->mutable_entity();
    entity->set_allocated_direct_counter_entry(direct_counter_entry);
    auto status = mgr.write(request);
    entity->release_direct_counter_entry();
    return status;
  }

  p4rt::DirectCounterEntry make_counter_entry(const p4rt::TableEntry *entry) {
    p4rt::DirectCounterEntry direct_counter_entry;
    if (entry) direct_counter_entry.mutable_table_entry()->CopyFrom(*entry);
    return direct_counter_entry;
  }

  pi_p4_id_t c_id;
};

TEST_F(DirectCounterTest, WriteAndRead) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto mk_matcher = CorrectMatchKey(t_id, mf);
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  {
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  auto entry_h = mock->get_table_entry_handle();

  auto counter_entry = make_counter_entry(&entry);
  auto *counter_data = counter_entry.mutable_data();
  counter_data->set_packet_count(3);
  // check packets, but not bytes, as per P4 program (packet-only counter)
  auto counter_matcher = CorrectCounterData(*counter_data, false, true);
  EXPECT_CALL(*mock, counter_write_direct(c_id, entry_h, counter_matcher));
  {
    auto status = write_counter(&counter_entry);
    ASSERT_EQ(status.code(), Code::OK);
  }

  // read with DirectCounterEntry
  EXPECT_CALL(*mock, counter_read_direct(c_id, entry_h, _, _));
  {
    p4rt::ReadResponse response;
    auto status = read_counter(&counter_entry, &response);
    ASSERT_EQ(status.code(), Code::OK);
    const auto &entities = response.entities();
    ASSERT_EQ(1, entities.size());
    const auto &read_entry = entities.Get(0).direct_counter_entry();
    EXPECT_TRUE(MessageDifferencer::Equals(entry, read_entry.table_entry()));
    EXPECT_EQ(read_entry.data().byte_count(), 0);
    EXPECT_EQ(read_entry.data().packet_count(), 3);
  }

  // read with TableEntry
  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  {
    p4rt::ReadResponse response;
    p4rt::Entity entity;
    auto table_entry = entity.mutable_table_entry();
    table_entry->set_table_id(t_id);
    table_entry->mutable_counter_data();
    auto status = mgr.read_one(entity, &response);

    ASSERT_EQ(status.code(), Code::OK);
    const auto &entities = response.entities();
    ASSERT_EQ(1, entities.size());
    const auto &read_entry = entities.Get(0).table_entry();
    EXPECT_EQ(read_entry.counter_data().byte_count(), 0);
    EXPECT_EQ(read_entry.counter_data().packet_count(), 3);
  }
}

TEST_F(DirectCounterTest, InvalidTableEntry) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto mk_matcher = CorrectMatchKey(t_id, mf);
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  {
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }

  std::string mf_1("\xaa\xbb\xcc\xee", 4);
  auto entry_1 = make_entry(mf_1, adata);
  auto counter_entry = make_counter_entry(&entry_1);
  {
    p4rt::ReadResponse response;
    auto status = read_counter(&counter_entry, &response);
    ASSERT_EQ(status.code(), Code::INVALID_ARGUMENT);
  }
}

// TODO(antonin)
TEST_F(DirectCounterTest, ReadAllFromTable) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto mk_matcher = CorrectMatchKey(t_id, mf);
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  {
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }

  p4rt::ReadResponse response;
  p4rt::DirectCounterEntry counter_entry;
  counter_entry.mutable_table_entry()->set_table_id(entry.table_id());
  auto status = read_counter(&counter_entry, &response);
  ASSERT_EQ(status.code(), Code::UNIMPLEMENTED);
}

TEST_F(DirectCounterTest, MissingTableEntry) {
  p4rt::ReadResponse response;
  p4rt::DirectCounterEntry counter_entry;
  auto status = read_counter(&counter_entry, &response);
  EXPECT_EQ(status.code(), Code::INVALID_ARGUMENT);
}

// TODO(antonin)
TEST_F(DirectCounterTest, ReadAll) {
  p4rt::ReadResponse response;
  p4rt::DirectCounterEntry counter_entry;
  counter_entry.mutable_table_entry();
  auto status = read_counter(&counter_entry, &response);
  ASSERT_EQ(status.code(), Code::UNIMPLEMENTED);
}

TEST_F(DirectCounterTest, WriteInTableEntry) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata);
  auto counter_data = entry.mutable_counter_data();
  counter_data->set_packet_count(3);

  auto mk_matcher = CorrectMatchKey(t_id, mf);
  auto *entry_matcher_ = new TableEntryMatcher_Direct(a_id, adata);
  // check packets, but not bytes, as per P4 program (packet-only counter)
  entry_matcher_->add_direct_counter(c_id, *counter_data, false, true);
  auto entry_matcher = ::testing::MakeMatcher(entry_matcher_);

  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  auto status = add_entry(&entry);
  EXPECT_EQ(status.code(), Code::OK);
}

class IndirectCounterTest : public DeviceMgrTest  {
 protected:
  IndirectCounterTest() {
    c_id = pi_p4info_counter_id_from_name(p4info, "CounterA");
    c_size = pi_p4info_counter_get_size(p4info, c_id);
  }

  // sends a read request for a CounterEntry; returns the RPC status
  DeviceMgr::Status read_counter(p4rt::CounterEntry *counter_entry,
                                 p4rt::ReadResponse *response) {
    p4rt::ReadRequest request;
    auto entity = request.add_entities();
    entity->set_allocated_counter_entry(counter_entry);
    auto status = mgr.read(request, response);
    entity->release_counter_entry();
    return status;
  }

  DeviceMgr::Status write_counter(p4rt::CounterEntry *counter_entry) {
    p4rt::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4rt::Update_Type_MODIFY);
    auto entity = update->mutable_entity();
    entity->set_allocated_counter_entry(counter_entry);
    auto status = mgr.write(request);
    entity->release_counter_entry();
    return status;
  }

  void set_index(p4rt::CounterEntry *counter_entry, int index) const {
    auto *index_msg = counter_entry->mutable_index();
    index_msg->set_index(index);
  }

  pi_p4_id_t c_id{0};
  size_t c_size{0};
};

TEST_F(IndirectCounterTest, WriteAndRead) {
  int index = 66;
  p4rt::ReadResponse response;
  p4rt::CounterEntry counter_entry;
  counter_entry.set_counter_id(c_id);
  set_index(&counter_entry, index);
  auto *counter_data = counter_entry.mutable_data();
  counter_data->set_packet_count(3);
  // check packets, but not bytes, as per P4 program (packet-only counter)
  auto counter_matcher = CorrectCounterData(*counter_data, false, true);
  EXPECT_CALL(*mock, counter_write(c_id, index, counter_matcher));
  {
    auto status = write_counter(&counter_entry);
    ASSERT_EQ(status.code(), Code::OK);
  }

  EXPECT_CALL(*mock, counter_read(c_id, index, _, _));
  {
    auto status = read_counter(&counter_entry, &response);
    ASSERT_EQ(status.code(), Code::OK);
  }
  const auto &entities = response.entities();
  ASSERT_EQ(1, entities.size());
  const auto &read_counter_entry = entities.Get(0).counter_entry();
  EXPECT_EQ(read_counter_entry.counter_id(), c_id);
  EXPECT_EQ(read_counter_entry.data().byte_count(), 0);
  EXPECT_EQ(read_counter_entry.data().packet_count(), 3);
}

TEST_F(IndirectCounterTest, ReadAll) {
  p4rt::ReadResponse response;
  p4rt::CounterEntry counter_entry;
  counter_entry.set_counter_id(c_id);

  // TODO(antonin): match index?
  EXPECT_CALL(*mock, counter_read(c_id, _, _, _)).Times(c_size);
  auto status = read_counter(&counter_entry, &response);
  ASSERT_EQ(status.code(), Code::OK);
  const auto &entities = response.entities();
  ASSERT_EQ(c_size, static_cast<size_t>(entities.size()));
  auto counter_data = counter_entry.mutable_data();
  counter_data->set_byte_count(0);
  counter_data->set_packet_count(0);
  for (size_t i = 0; i < c_size; i++) {
    const auto &entry = entities.Get(i).counter_entry();
    set_index(&counter_entry, i);
    ASSERT_TRUE(MessageDifferencer::Equals(counter_entry, entry));
  }
}


// Only testing for exact match tables for now, there is not much code variation
// between different table types.
// I added some tests specific to Ternary, Range and LPM below (TernaryOneTest,
// RangeOneTest and LpmOneTest).
class MatchKeyFormatTest : public ExactOneTest {
 protected:
  MatchKeyFormatTest()
      : ExactOneTest("ExactOneNonAligned", "header_test.field12") { }

  p4rt::TableEntry make_entry_no_mk() {
    p4rt::TableEntry table_entry;
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

  void add_one_mf(p4rt::TableEntry *entry, const std::string &mf_v) {
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
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

TEST_F(MatchKeyFormatTest, MkTooLong) {
  auto entry = make_entry_no_mk();
  std::string mf_v("\x0a\xbb", 2);
  add_one_mf(&entry, mf_v);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

TEST_F(MatchKeyFormatTest, FieldTooShort) {
  auto entry = make_entry_no_mk();
  std::string mf_v("\x0a", 1);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

TEST_F(MatchKeyFormatTest, FieldTooLong) {
  auto entry = make_entry_no_mk();
  std::string mf_v("\xaa\xbb\xcc", 3);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

TEST_F(MatchKeyFormatTest, BadLeadingZeros) {
  auto entry = make_entry_no_mk();
  std::string mf_v("\x10\xbb", 2);
  add_one_mf(&entry, mf_v);
  auto status = add_entry(&entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}


#define EXPECT_ONE_TABLE_ENTRY(response, expected_entry) \
  do {                                                   \
    const auto &entities = response.entities();          \
    ASSERT_EQ(1, entities.size());                       \
    EXPECT_TRUE(MessageDifferencer::Equals(              \
        expected_entry, entities.Get(0).table_entry())); \
  } while (false)

class TernaryOneTest : public DeviceMgrTest {
 protected:
  TernaryOneTest(const std::string &t_name, const std::string &f_name)
      : f_name(f_name) {
    t_id = pi_p4info_table_id_from_name(p4info, t_name.c_str());
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  }

  TernaryOneTest()
      : TernaryOneTest("TernaryOne", "header_test.field32") { }

  p4rt::TableEntry make_entry(const boost::optional<std::string> &mf_v,
                              const boost::optional<std::string> &mask_v,
                              const std::string &param_v) {
    p4rt::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    // not supported by older versions of boost
    // if (mf_v != boost::none) {
    if (mf_v.is_initialized()) {
      auto mf = table_entry.add_match();
      mf->set_field_id(pi_p4info_table_match_field_id_from_name(
          p4info, t_id, f_name.c_str()));
      auto mf_ternary = mf->mutable_ternary();
      mf_ternary->set_value(*mf_v);
      mf_ternary->set_mask(*mask_v);
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

  const std::string f_name;
  pi_p4_id_t t_id;
  pi_p4_id_t a_id;
};

TEST_F(TernaryOneTest, ValueEqValueAndMask) {
  std::string adata(6, '\x00');
  {  // value == value & mask
    std::string mf("\x11\x01\x01\x00", 4);
    std::string mask("\xff\xff\xff\xff", 4);
    auto entry = make_entry(mf, mask, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  {  // value != value & mask
    std::string mf("\x11\x01\x01\x00", 4);
    std::string mask("\xff\x00\xff\xff", 4);
    auto entry = make_entry(mf, mask, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(0);
    auto status = add_entry(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
}

TEST_F(TernaryOneTest, DontCare) {
  std::string adata(6, '\x00');
  {  // omitting match field: valid
    auto entry = make_entry(boost::none, boost::none, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);

    p4rt::ReadResponse response;
    {
      EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
      auto status = read_table_entries(t_id, &response);
      ASSERT_EQ(status.code(), Code::OK);
    }
    EXPECT_ONE_TABLE_ENTRY(response, entry);
  }
  {  // zero mask: invalid
    std::string mf("\x11\x01\x01\x00", 4);
    std::string mask(4, '\x00');
    auto entry = make_entry(mf, mask, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(0);
    auto status = add_entry(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
}

class RangeOneTest : public DeviceMgrTest {
 protected:
  RangeOneTest(const std::string &t_name, const std::string &f_name)
      : f_name(f_name) {
    t_id = pi_p4info_table_id_from_name(p4info, t_name.c_str());
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  }

  RangeOneTest()
      : RangeOneTest("RangeOne", "header_test.field32") { }

  p4rt::TableEntry make_entry(const boost::optional<std::string> &low_v,
                            const boost::optional<std::string> &high_v,
                            const std::string &param_v) {
    p4rt::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    // not supported by older versions of boost
    // if (low_v != boost::none) {
    if (low_v.is_initialized()) {
      auto mf = table_entry.add_match();
      mf->set_field_id(pi_p4info_table_match_field_id_from_name(
          p4info, t_id, f_name.c_str()));
      auto mf_range = mf->mutable_range();
      mf_range->set_low(*low_v);
      mf_range->set_high(*high_v);
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

  const std::string f_name;
  pi_p4_id_t t_id;
  pi_p4_id_t a_id;
};

TEST_F(RangeOneTest, LowLeHigh) {
  std::string adata(6, '\x00');
  {  // low < high
    std::string low("\x11\x00\x11\x11", 4);
    std::string high("\x11\x00\x12\x11", 4);
    auto entry = make_entry(low, high, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  {  // low == high
    std::string low("\x11\x00\x11\x11", 4);
    std::string high(low);
    auto entry = make_entry(low, high, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  {  // low > high
    std::string low("\x11\x00\x12\x11", 4);
    std::string high("\x11\x00\x11\x11", 4);
    auto entry = make_entry(low, high, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(0);
    auto status = add_entry(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
}

TEST_F(RangeOneTest, DontCare) {
  std::string adata(6, '\x00');
  {  // omitting match field: valid
    auto entry = make_entry(boost::none, boost::none, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);

    p4rt::ReadResponse response;
    {
      EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
      auto status = read_table_entries(t_id, &response);
      ASSERT_EQ(status.code(), Code::OK);
    }
    EXPECT_ONE_TABLE_ENTRY(response, entry);
  }
  {  // low=0, high=2**bitwidth-1: invalid
    std::string low(4, '\x00');
    std::string high(4, '\xff');
    auto entry = make_entry(low, high, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(0);
    auto status = add_entry(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
}

class LpmOneTest : public DeviceMgrTest {
 protected:
  LpmOneTest(const std::string &t_name, const std::string &f_name)
      : f_name(f_name) {
    t_id = pi_p4info_table_id_from_name(p4info, t_name.c_str());
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  }

  LpmOneTest()
      : LpmOneTest("LpmOne", "header_test.field32") { }

  p4rt::TableEntry make_entry(const boost::optional<std::string> &mf_v,
                              int pLen,
                              const std::string &param_v) {
    p4rt::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    // not supported by older versions of boost
    // if (mf_v != boost::none) {
    if (mf_v.is_initialized()) {
      auto mf = table_entry.add_match();
      mf->set_field_id(pi_p4info_table_match_field_id_from_name(
          p4info, t_id, f_name.c_str()));
      auto mf_lpm = mf->mutable_lpm();
      mf_lpm->set_value(*mf_v);
      mf_lpm->set_prefix_len(pLen);
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

  const std::string f_name;
  pi_p4_id_t t_id;
  pi_p4_id_t a_id;
};

TEST_F(LpmOneTest, TrailingZeros) {
  std::string adata(6, '\x00');
  int pLen(12);
  {
    std::string mf("\xff\xf0\x00\x00", 4);
    auto entry = make_entry(mf, pLen, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  {
    std::string mf("\xff\x80\x00\x00", 4);
    auto entry = make_entry(mf, pLen, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  }
  {
    std::string mf("\xff\xff\x00\x00", 4);
    auto entry = make_entry(mf, pLen, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(0);
    auto status = add_entry(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
  {
    std::string mf("\xff\xff\x0f\x00", 4);
    auto entry = make_entry(mf, pLen, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(0);
    auto status = add_entry(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
}

TEST_F(LpmOneTest, DontCare) {
  std::string adata(6, '\x00');
  int pLen(0);
  {  // omitting match field: valid
    auto entry = make_entry(boost::none, pLen, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);

    p4rt::ReadResponse response;
    {
      EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
      auto status = read_table_entries(t_id, &response);
      ASSERT_EQ(status.code(), Code::OK);
    }
    EXPECT_ONE_TABLE_ENTRY(response, entry);
  }
  {  // pLen=0: invalid
    std::string mf("\xff\xf0\x00\x00", 4);
    auto entry = make_entry(mf, pLen, adata);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(0);
    auto status = add_entry(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
}

#undef EXPECT_ONE_TABLE_ENTRY

class TernaryTwoTest : public DeviceMgrTest {
 protected:
  TernaryTwoTest() {
    t_id = pi_p4info_table_id_from_name(p4info, "TernaryTwo");
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  }

  p4rt::TableEntry make_entry(const std::string &mf1_v,
                              const std::string &mask1_v,
                              const std::string &mf2_v,
                              const std::string &mask2_v,
                              const std::string &param_v) {
    p4rt::TableEntry table_entry;
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
  auto mk_matcher = CorrectMatchKey(t_id, mk);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, _, _));
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);
}


// Placeholder for PRE tests: for now there is no support in DeviceMgr
class PRETest : public DeviceMgrTest { };

TEST_F(PRETest, Write) {
  p4rt::WriteRequest request;
  auto *update = request.add_updates();
  update->set_type(p4rt::Update_Type_MODIFY);
  auto *entity = update->mutable_entity();
  auto *pre_entry = entity->mutable_packet_replication_engine_entry();
  auto *mg_entry = pre_entry->mutable_multicast_group_entry();
  mg_entry->set_multicast_group_id(1);
  auto *replica = mg_entry->add_replicas();
  replica->set_egress_port(1);
  replica->set_instance(1);

  auto status = mgr.write(request);
  EXPECT_EQ(status, OneExpectedError(Code::UNIMPLEMENTED));
}

TEST_F(PRETest, Read) {
  p4rt::ReadRequest request;
  p4rt::ReadResponse response;
  auto *entity = request.add_entities();
  // set oneof to PRE
  auto *pre_entry = entity->mutable_packet_replication_engine_entry();
  (void) pre_entry;

  auto status = mgr.read(request, &response);
  EXPECT_EQ(status.code(), Code::UNIMPLEMENTED);
}

class ReadConstTableTest : public DeviceMgrTest {
 protected:
  ReadConstTableTest() {
    t_id = pi_p4info_table_id_from_name(p4info, "ConstTable");
    a_id = pi_p4info_action_id_from_name(p4info, "actionB");
  }

  void SetUp() override {
    DeviceMgrTest::SetUp();
    std::ifstream istream(entries_path);
    google::protobuf::io::IstreamInputStream istream_(&istream);
    google::protobuf::TextFormat::Parse(&istream_, &const_entries_request);
  }

  static constexpr const char *entries_path =
      TESTDATADIR "/" "unittest.entries.txt";

  pi_p4_id_t t_id;
  pi_p4_id_t a_id;
  p4rt::WriteRequest const_entries_request;
};

// This test is not representative of what bmv2 does. In bmv2 const entries are
// read from the bmv2 JSON and not added through the P4Runtime service /
// DeviceMgr. Here we use the p4runtime entries file generated by the p4c
// compiler to install the entries so this test is actually not very different
// from reading from a "normal" table.
TEST_F(ReadConstTableTest, P4RuntimeEntries) {
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(AnyNumber());
  {
    auto status = mgr.write(const_entries_request);
    ASSERT_EQ(status.code(), Code::OK);
  }

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _)).Times(AnyNumber());
  p4rt::ReadResponse response;
  auto status = read_table_entries(t_id, &response);
  EXPECT_EQ(status.code(), Code::OK);
}

// This test on the other hand is representative of what bmv2 does. We by-pass
// DeviceMgr by using the C++ PI frontend directly.
TEST_F(ReadConstTableTest, OutOfBandEntries) {
  struct SessionTemp {
    SessionTemp() { pi_session_init(&sess); }
    ~SessionTemp() { pi_session_cleanup(sess); }
    pi_session_handle_t operator*() const { return sess; }
    pi_session_handle_t sess;
  };

  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(AnyNumber());
  SessionTemp session;
  pi::MatchTable mt(*session, {device_id, 0}, p4info, t_id);
  for (const auto &update : const_entries_request.updates()) {
    pi::MatchKey mk(p4info, t_id);
    const auto &table_entry = update.entity().table_entry();
    const auto &mf = table_entry.match(0);
    const auto &mf_v = mf.exact().value();
    mk.set_exact(mf.field_id(), mf_v.data(), mf_v.size());
    pi::ActionEntry action_entry;
    action_entry.init_action_data(p4info, a_id);
    auto *action_data = action_entry.mutable_action_data();
    const auto &action = table_entry.action().action();
    const auto &param = action.params(0);
    const auto &param_v = param.value();
    action_data->set_arg(param.param_id(), param_v.data(), param_v.size());

    pi_entry_handle_t entry_h;
    EXPECT_EQ(mt.entry_add(mk, action_entry, false, &entry_h),
              PI_STATUS_SUCCESS);
  }

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _)).Times(AnyNumber());
  p4rt::ReadResponse response;
  auto status = read_table_entries(t_id, &response);
  EXPECT_EQ(status.code(), Code::OK);
}


// Placeholder for PVS (Parser Value Set) tests: for now there is no support in
// DeviceMgr
class PVSTest : public DeviceMgrTest { };

TEST_F(PVSTest, Write) {
  p4rt::WriteRequest request;
  auto *update = request.add_updates();
  update->set_type(p4rt::Update_Type_MODIFY);
  auto *entity = update->mutable_entity();
  auto *pvs_entry = entity->mutable_value_set_entry();
  (void) pvs_entry;
  auto status = mgr.write(request);
  EXPECT_EQ(status, OneExpectedError(Code::UNIMPLEMENTED));
}

TEST_F(PVSTest, Read) {
  p4rt::ReadRequest request;
  p4rt::ReadResponse response;
  auto *entity = request.add_entities();
  // set oneof to PVS
  auto *pvs_entry = entity->mutable_value_set_entry();
  (void) pvs_entry;
  auto status = mgr.read(request, &response);
  EXPECT_EQ(status.code(), Code::UNIMPLEMENTED);
}

// Placeholder for Register tests: for now there is no support in DeviceMgr
class RegisterTest : public DeviceMgrTest { };

TEST_F(RegisterTest, Write) {
  p4rt::WriteRequest request;
  auto *update = request.add_updates();
  update->set_type(p4rt::Update_Type_MODIFY);
  auto *entity = update->mutable_entity();
  auto *register_entry = entity->mutable_register_entry();
  (void) register_entry;
  auto status = mgr.write(request);
  EXPECT_EQ(status, OneExpectedError(Code::UNIMPLEMENTED));
}

TEST_F(RegisterTest, Read) {
  p4rt::ReadRequest request;
  p4rt::ReadResponse response;
  auto *entity = request.add_entities();
  auto *register_entry = entity->mutable_register_entry();
  (void) register_entry;
  auto status = mgr.read(request, &response);
  EXPECT_EQ(status.code(), Code::UNIMPLEMENTED);
}

// Placeholder for Digest tests: for now there is no support in DeviceMgr
class DigestTest : public DeviceMgrTest { };

TEST_F(DigestTest, Write) {
  p4rt::WriteRequest request;
  auto *update = request.add_updates();
  update->set_type(p4rt::Update_Type_MODIFY);
  auto *entity = update->mutable_entity();
  auto *register_entry = entity->mutable_register_entry();
  (void) register_entry;
  auto status = mgr.write(request);
  EXPECT_EQ(status, OneExpectedError(Code::UNIMPLEMENTED));
}

TEST_F(DigestTest, Read) {
  p4rt::ReadRequest request;
  p4rt::ReadResponse response;
  auto *entity = request.add_entities();
  auto *register_entry = entity->mutable_register_entry();
  (void) register_entry;
  auto status = mgr.read(request, &response);
  EXPECT_EQ(status.code(), Code::UNIMPLEMENTED);
}

// This test verifies that the ReadRequest gets a unique lock (no concurrent
// writes).
// We inherit from MatchTableIndirectTest as a convenience (to access all table
// / action profile modifiers).
class ReadExclusiveAccess : public MatchTableIndirectTest {
 public:
  ReadExclusiveAccess() {
    t_id = pi_p4info_table_id_from_name(p4info, "IndirectWS");
    act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  }

 protected:
  pi_p4_id_t t_id;
  pi_p4_id_t act_prof_id;
};

TEST_F(ReadExclusiveAccess, ConcurrentReadAndWrites) {
  // one thread 1) adds action profile member, 2) adds table entry pointing to
  // this member, 3) deletes table entry and 4) deletes member
  // another thread reads action profile and table entry
  // the test ensures that in the read response, we either have a) an empty
  // table and an empty action profile, b) both the member and the table
  // entry, or c) just the member. Based on read semantics, we cannot have just
  // the table entry!!!

  auto do_write = [this](size_t iters) {
    EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _))
        .Times(iters);
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(iters);
    EXPECT_CALL(*mock, table_entry_delete_wkey(t_id, _)).Times(iters);
    EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, _)).Times(iters);

    uint32_t member_id = 123;
    std::string mf("\xaa\xbb\xcc\xdd", 4);
    std::string adata(6, '\x00');
    auto member = make_member(member_id, adata);
    auto entry = make_indirect_entry_to_member(mf, member_id);

    std::vector<p4rt::WriteRequest> requests(4);
    {
      auto &request = requests.at(0);
      auto *update = request.add_updates();
      update->set_type(p4rt::Update_Type_INSERT);
      auto *entity = update->mutable_entity();
      entity->mutable_action_profile_member()->CopyFrom(member);
    }
    {
      auto &request = requests.at(1);
      auto *update = request.add_updates();
      update->set_type(p4rt::Update_Type_INSERT);
      auto *entity = update->mutable_entity();
      entity->mutable_table_entry()->CopyFrom(entry);
    }
    {
      auto &request = requests.at(2);
      auto *update = request.add_updates();
      update->set_type(p4rt::Update_Type_DELETE);
      auto *entity = update->mutable_entity();
      entity->mutable_table_entry()->CopyFrom(entry);
    }
    {
      auto &request = requests.at(3);
      auto *update = request.add_updates();
      update->set_type(p4rt::Update_Type_DELETE);
      auto *entity = update->mutable_entity();
      entity->mutable_action_profile_member()->CopyFrom(member);
    }

    for (size_t i = 0; i < iters; i++) {
      for (const auto &request : requests) {
        auto status = mgr.write(request);
        EXPECT_EQ(status.code(), Code::OK);
      }
    }
  };

  std::atomic<bool> stop{false};

  auto do_read = [this, &stop]() {
    EXPECT_CALL(*mock, table_entries_fetch(t_id, _)).Times(AtLeast(1));
    EXPECT_CALL(*mock, action_prof_entries_fetch(act_prof_id, _))
        .Times(AtLeast(1));
    p4rt::ReadRequest request;
    {
      auto *entity = request.add_entities();
      auto *entry = entity->mutable_table_entry();
      entry->set_table_id(t_id);
    }
    {
      auto *entity = request.add_entities();
      auto *member = entity->mutable_action_profile_member();
      member->set_action_profile_id(act_prof_id);
    }
    while (!stop) {
      p4rt::ReadResponse response;
      auto status = mgr.read(request, &response);
      ASSERT_EQ(status.code(), Code::OK);
      const auto num_objects = response.entities_size();
      ASSERT_TRUE(num_objects == 0 ||
                  num_objects == 2 ||
                  (num_objects == 1 &&
                   response.mutable_entities(0)->has_action_profile_member()));
    }
  };

  // 10,000 iterations
  size_t iterations = 10000u;

  std::thread t2(do_read);  // make sure we start reading before writing
  std::thread t1(do_write, iterations);

  t1.join();
  stop = true;
  t2.join();
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
