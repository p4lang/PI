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
#include <chrono>
#include <condition_variable>
#include <cstring>  // std::memcmp
#include <fstream>  // std::ifstream
#include <iterator>  // std::distance
#include <memory>
#include <mutex>
#include <ostream>
#include <queue>
#include <regex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "p4/tmp/p4config.pb.h"

#include "PI/frontends/cpp/tables.h"
#include "PI/frontends/proto/device_mgr.h"
#include "PI/int/pi_int.h"
#include "PI/p4info.h"
#include "PI/pi.h"
#include "PI/proto/util.h"

#include "PI/proto/p4info_to_and_from_proto.h"

#include "google/rpc/code.pb.h"

#include "matchers.h"
#include "mock_switch.h"

namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;

// Needs to be in same namespace as google::rpc::Status for ADL
namespace google {
namespace rpc {
std::ostream &operator<<(std::ostream &out, const Status &status) {
  out << "Status(code=" << status.code() << ", message='" << status.message()
      << "', details=";
  for (const auto &error_any : status.details()) {
    p4v1::Error error;
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
using ::testing::Args;
using ::testing::AtLeast;
using ::testing::ElementsAre;
using ::testing::Exactly;
using ::testing::IsNull;
using ::testing::Return;

// Used to make sure that a google::rpc::Status object has the correct format
// and contains a single p4v1::Error message with a matching canonical error
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
  p4v1::Error error;
  if (!error_any.UnpackTo(&error)) return false;
  if (error.canonical_code() != expected.code) return false;
  if (!expected.msg.empty() &&
      !std::regex_search(error.message(), std::regex(expected.msg))) {
    return false;
  }
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
  if (!error.msg.empty()) out << ", message regex='" << error.msg << "'";
  return out;
}

// Used to make sure that a google::rpc::Status object has the correct format
// and contains the correct error codes in the details field, which is a
// repeated field of p4v1::Error messages (as Any messages).
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
    p4v1::Error error;
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
    p4v1::ForwardingPipelineConfig config;
    config.set_allocated_p4info(&p4info_proto);
    config.mutable_cookie()->set_cookie(cookie);
    p4::tmp::P4DeviceConfig dummy_device_config_;
    dummy_device_config_.set_device_data("This is a dummy device config");
    dummy_device_config_.SerializeToString(&dummy_device_config);
    config.set_p4_device_config(dummy_device_config);
    EXPECT_CALL(*mock, action_prof_api_support())
        .WillRepeatedly(Return(action_prof_api_choice));
    EXPECT_CALL(*mock, table_idle_timeout_config_set(
        pi_p4info_table_id_from_name(p4info, "IdleTimeoutTable"), _));
    auto status = mgr.pipeline_config_set(
        p4v1::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT,
        config);
    // releasing resource before the assert to avoid double free in case the
    // assert is false
    config.release_p4info();
    ASSERT_OK(status);
  }

  void TearDown() override { }

  DeviceMgr::Status generic_write(p4v1::Update::Type type,
                                  p4v1::TableEntry *entry) {
    p4v1::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(type);
    auto entity = update->mutable_entity();
    entity->set_allocated_table_entry(entry);
    auto status = mgr.write(request);
    entity->release_table_entry();
    return status;
  }

  DeviceMgr::Status add_entry(p4v1::TableEntry *entry) {
    return generic_write(p4v1::Update::INSERT, entry);
  }

  DeviceMgr::Status remove_entry(p4v1::TableEntry *entry) {
    return generic_write(p4v1::Update::DELETE, entry);
  }

  DeviceMgr::Status modify_entry(p4v1::TableEntry *entry) {
    return generic_write(p4v1::Update::MODIFY, entry);
  }

  DeviceMgr::Status read_table_entries(pi_p4_id_t t_id,
                                       p4v1::ReadResponse *response) {
    p4v1::Entity entity;
    auto table_entry = entity.mutable_table_entry();
    table_entry->set_table_id(t_id);
    return mgr.read_one(entity, response);
  }

  DeviceMgr::Status read_table_entry(p4v1::TableEntry *table_entry,
                                     p4v1::ReadResponse *response) {
    p4v1::Entity entity;
    entity.set_allocated_table_entry(table_entry);
    auto status = mgr.read_one(entity, response);
    entity.release_table_entry();
    return status;
  }

  static constexpr const char *input_path =
           TESTDATADIR "/" "unittest.p4info.txt";
  static pi_p4info_t *p4info;
  static p4configv1::P4Info p4info_proto;
  static constexpr const char *invalid_p4_id_error_str = "Invalid P4 id";

  DummySwitchWrapper wrapper{};
  DummySwitchMock *mock;
  device_id_t device_id;
  DeviceMgr mgr;
  uint64_t cookie{666};
  PiActProfApiSupport action_prof_api_choice{PiActProfApiSupport_BOTH};
  std::string dummy_device_config;
};

pi_p4info_t *DeviceMgrTest::p4info = nullptr;
p4configv1::P4Info DeviceMgrTest::p4info_proto;
constexpr const char *DeviceMgrTest::invalid_p4_id_error_str;

TEST_F(DeviceMgrTest, ResourceTypeFromId) {
  using Type = p4configv1::P4Ids;
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
  using GetConfigRequest = p4v1::GetForwardingPipelineConfigRequest;
  {
    p4v1::ForwardingPipelineConfig config;
    auto status = mgr.pipeline_config_get(GetConfigRequest::ALL, &config);
    ASSERT_OK(status);
    EXPECT_TRUE(MessageDifferencer::Equals(config.p4info(), p4info_proto));
    EXPECT_EQ(config.cookie().cookie(), cookie);
    EXPECT_EQ(config.p4_device_config(), dummy_device_config);
  }
  {
    p4v1::ForwardingPipelineConfig config;
    auto status = mgr.pipeline_config_get(
        GetConfigRequest::COOKIE_ONLY, &config);
    ASSERT_OK(status);
    EXPECT_FALSE(config.has_p4info());
    EXPECT_EQ(config.cookie().cookie(), cookie);
    EXPECT_EQ(config.p4_device_config(), "");
  }
  {
    p4v1::ForwardingPipelineConfig config;
    auto status = mgr.pipeline_config_get(
        GetConfigRequest::P4INFO_AND_COOKIE, &config);
    ASSERT_OK(status);
    EXPECT_TRUE(MessageDifferencer::Equals(config.p4info(), p4info_proto));
    EXPECT_EQ(config.cookie().cookie(), cookie);
    EXPECT_EQ(config.p4_device_config(), "");
  }
  {
    p4v1::ForwardingPipelineConfig config;
    auto status = mgr.pipeline_config_get(
        GetConfigRequest::DEVICE_CONFIG_AND_COOKIE, &config);
    ASSERT_OK(status);
    EXPECT_FALSE(config.has_p4info());
    EXPECT_EQ(config.cookie().cookie(), cookie);
    EXPECT_EQ(config.p4_device_config(), dummy_device_config);
  }
}

TEST_F(DeviceMgrTest, PipelineConfigGetLarge) {
  std::string large_device_config;
  {
    p4v1::ForwardingPipelineConfig config;
    config.mutable_p4info()->CopyFrom(p4info_proto);
    p4::tmp::P4DeviceConfig large_device_config_;
    large_device_config_.set_device_data(std::string(32768, 'a'));
    large_device_config_.SerializeToString(&large_device_config);
    config.set_p4_device_config(large_device_config);
    EXPECT_CALL(*mock, table_idle_timeout_config_set(
        pi_p4info_table_id_from_name(p4info, "IdleTimeoutTable"), _));
    ASSERT_OK(mgr.pipeline_config_set(
        p4v1::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT,
        config));
  }
  using GetConfigRequest = p4v1::GetForwardingPipelineConfigRequest;
  {
    p4v1::ForwardingPipelineConfig config;
    ASSERT_OK(mgr.pipeline_config_get(GetConfigRequest::ALL, &config));
    EXPECT_TRUE(MessageDifferencer::Equals(config.p4info(), p4info_proto));
    EXPECT_FALSE(config.has_cookie());
    // avoid printing the large strings in case of failure
    EXPECT_TRUE(config.p4_device_config() == large_device_config)
        << "Large device config does not match.";
  }
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

  p4v1::FieldMatch get_proto(pi_p4_id_t f_id) const {
    p4v1::FieldMatch fm;
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

#define PRIORITY 77

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

  p4v1::TableEntry generic_make(pi_p4_id_t t_id,
                                boost::optional<p4v1::FieldMatch> mf,
                                const std::string &param_v,
                                int priority = 0,
                                uint64_t controller_metadata = 0);

  boost::optional<MatchKeyInput> default_mf() const;

  pi_p4_id_t t_id;
  pi_p4_id_t mf_id;
  pi_p4_id_t a_id;
};

p4v1::TableEntry
MatchTableTest::generic_make(pi_p4_id_t t_id,
                             boost::optional<p4v1::FieldMatch> mf,
                             const std::string &param_v,
                             int priority,
                             uint64_t controller_metadata) {
  p4v1::TableEntry table_entry;
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
          std::string(4, '\x00'), std::string(4, '\x00'), PRIORITY);
    case MatchKeyInput::Type::RANGE:
      return MatchKeyInput::make_range(
          std::string(4, '\x00'), std::string(4, '\xff'), PRIORITY);
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
    auto status = add_entry(&entry);
    EXPECT_EQ(status.code(), Code::OK);
  }
  // second is error because duplicate match key
  {
    auto status = add_entry(&entry);
    EXPECT_EQ(status, OneExpectedError(Code::ALREADY_EXISTS));
  }

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _)).Times(2);
  // 2 different reads: first one is wildcard read on the table, other filters
  // on the match key.
  {
    p4v1::ReadResponse response;
    auto status = read_table_entries(t_id, &response);
    ASSERT_EQ(status.code(), Code::OK);
    const auto &entities = response.entities();
    ASSERT_EQ(1, entities.size());
    EXPECT_TRUE(
        MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
  }
  {
    p4v1::ReadResponse response;
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
  status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entry_delete_wkey(t_id, mk_matcher))
      .Times(AtLeast(1));
  status = remove_entry(&entry);
  EXPECT_EQ(status.code(), Code::OK);
  // second call is error because match key has been removed already
  status = remove_entry(&entry);
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
  status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  std::string new_adata(6, '\xaa');
  auto new_entry_matcher = CorrectTableEntryDirect(a_id, new_adata);
  auto new_entry = generic_make(
      t_id, mk_input.get_proto(mf_id), adata, mk_input.get_priority());
  EXPECT_CALL(*mock, table_entry_modify_wkey(t_id, mk_matcher, entry_matcher));
  status = modify_entry(&new_entry);
  EXPECT_EQ(status.code(), Code::OK);
}

TEST_P(MatchTableTest, SetDefault) {
  std::string adata(6, '\x00');
  auto entry_matcher = CorrectTableEntryDirect(a_id, adata);
  EXPECT_CALL(*mock, table_default_action_set(t_id, entry_matcher)).Times(2);
  auto entry = generic_make(t_id, boost::none, adata);
  entry.set_is_default_action(true);
  {
    auto status = add_entry(&entry);
    // cannot INSERT default entries
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
  EXPECT_OK(modify_entry(&entry));
  EXPECT_OK(modify_entry(&entry));
  EXPECT_CALL(*mock, table_default_action_reset(t_id));
  entry.clear_action();
  EXPECT_OK(modify_entry(&entry));
  {
    auto status = remove_entry(&entry);
    // cannot DELETE default entries
    EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
  }
}

TEST_P(MatchTableTest, InvalidSetDefault) {
  // Invalid to set is_default_action flag to true with a non-empty match key
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata);
  entry.set_is_default_action(true);
  auto status = add_entry(&entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

TEST_P(MatchTableTest, ResetDefaultBeforeSet) {
  p4v1::TableEntry entry;
  entry.set_table_id(t_id);
  entry.set_is_default_action(true);
  EXPECT_CALL(*mock, table_default_action_reset(t_id));
  auto status = modify_entry(&entry);
  EXPECT_EQ(status.code(), Code::OK);
}

TEST_P(MatchTableTest, InvalidTableId) {
  // build valid table entry, then modify the table id
  std::string adata(6, '\x00');
  auto mk_input = std::get<1>(GetParam());
  auto entry = generic_make(t_id, mk_input.get_proto(mf_id), adata);
  auto check_bad_status_write = [this, &entry](pi_p4_id_t bad_id) {
    entry.set_table_id(bad_id);
    auto status = add_entry(&entry);
    EXPECT_EQ(
        status,
        OneExpectedError(Code::INVALID_ARGUMENT, invalid_p4_id_error_str));
  };
  auto check_bad_status_read = [this](pi_p4_id_t bad_id) {
    p4v1::ReadResponse response;
    p4v1::Entity entity;
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
  auto entry = generic_make(
      t_id, mk_input.get_proto(mf_id), adata, mk_input.get_priority());
  auto check_bad_status_write = [this, &entry](
      pi_p4_id_t bad_id, const char *msg = invalid_p4_id_error_str) {
    auto action = entry.mutable_action()->mutable_action();
    action->set_action_id(bad_id);
    auto status = add_entry(&entry);
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
    auto entry = generic_make(
        t_id, boost::none, adata, mk_input->get_priority());
    auto status = add_entry(&entry);
    ASSERT_EQ(status.code(), Code::OK);
  } else {  // omitting field not supported for match type
    auto entry = generic_make(t_id, boost::none, adata, 0);
    auto status = add_entry(&entry);
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
  p4v1::WriteRequest request;
  {
    auto update = request.add_updates();
    update->set_type(p4v1::Update::DELETE);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(entry);
    expected_errors.push_back(Code::NOT_FOUND);
  }
  {
    auto update = request.add_updates();
    update->set_type(p4v1::Update::INSERT);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(entry);
    expected_errors.push_back(Code::OK);
  }
  {
    auto update = request.add_updates();
    update->set_type(p4v1::Update::INSERT);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(entry);
    expected_errors.push_back(Code::ALREADY_EXISTS);
  }
  {
    auto update = request.add_updates();
    update->set_type(p4v1::Update::DELETE);
    update->mutable_entity()->mutable_table_entry()->CopyFrom(entry);
    expected_errors.push_back(Code::OK);
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


// some helper macros to make the tests below a bit easier to read (maybe?)
#define EXPECT_CALL_GROUP_SET_MEMBERS(mock, ...) \
  EXPECT_CALL(mock, action_prof_group_set_members(__VA_ARGS__))
#define EXPECT_CALL_GROUP_ADD_MEMBER(mock, ...) \
  EXPECT_CALL(mock, action_prof_group_add_member(__VA_ARGS__))
#define EXPECT_CALL_GROUP_REMOVE_MEMBER(mock, ...) \
  EXPECT_CALL(mock, action_prof_group_remove_member(__VA_ARGS__))

#define EXPECT_NO_CALL_GROUP_ADD_MEMBER(mock) \
  EXPECT_CALL(mock, action_prof_group_add_member(_, _, _)).Times(0)
#define EXPECT_NO_CALL_GROUP_REMOVE_MEMBER(mock) \
  EXPECT_CALL(mock, action_prof_group_remove_member(_, _, _)).Times(0)
#define EXPECT_NO_CALL_GROUP_SET_MEMBERS(mock) \
  EXPECT_CALL(mock, action_prof_group_set_members(_, _, _, _)).Times(0)

class ActionProfTest
    : public DeviceMgrTest, public WithParamInterface<PiActProfApiSupport> {
 protected:
  ActionProfTest() {
    action_prof_api_choice = GetParam();
  }

  void set_action(p4v1::Action *action, const std::string &param_v) {
    auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    param->set_value(param_v);
  }

  p4v1::ActionProfileMember make_member(uint32_t member_id,
                                        const std::string &param_v = "") {
    p4v1::ActionProfileMember member;
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    member.set_action_profile_id(act_prof_id);
    member.set_member_id(member_id);
    set_action(member.mutable_action(), param_v);
    return member;
  }

  DeviceMgr::Status write_member(p4v1::Update::Type type,
                                 p4v1::ActionProfileMember *member) {
    p4v1::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(type);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_member(member);
    auto status = mgr.write(request);
    entity->release_action_profile_member();
    return status;
  }

  DeviceMgr::Status create_member(p4v1::ActionProfileMember *member) {
    return write_member(p4v1::Update::INSERT, member);
  }

  DeviceMgr::Status modify_member(p4v1::ActionProfileMember *member) {
    return write_member(p4v1::Update::MODIFY, member);
  }

  DeviceMgr::Status delete_member(p4v1::ActionProfileMember *member) {
    return write_member(p4v1::Update::DELETE, member);
  }

  void add_member_to_group(p4v1::ActionProfileGroup *group,
                           uint32_t member_id,
                           int weight = 1) {
    auto member = group->add_members();
    member->set_member_id(member_id);
    member->set_weight(weight);
  }

  template <typename It>
  p4v1::ActionProfileGroup make_group(uint32_t group_id,
                                      It members_begin, It members_end) {
    p4v1::ActionProfileGroup group;
    auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    group.set_action_profile_id(act_prof_id);
    group.set_group_id(group_id);
    for (auto it = members_begin; it != members_end; ++it) {
      auto member = group.add_members();
      member->set_member_id(*it);
      member->set_weight(1);
    }
    return group;
  }

  p4v1::ActionProfileGroup make_group(uint32_t group_id) {
    std::vector<uint32_t> members;
    return make_group(group_id, members.begin(), members.end());
  }

  DeviceMgr::Status write_group(p4v1::Update::Type type,
                                p4v1::ActionProfileGroup *group) {
    p4v1::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(type);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_group(group);
    auto status = mgr.write(request);
    entity->release_action_profile_group();
    return status;
  }

  DeviceMgr::Status create_group(p4v1::ActionProfileGroup *group) {
    return write_group(p4v1::Update::INSERT, group);
  }

  DeviceMgr::Status modify_group(p4v1::ActionProfileGroup *group) {
    return write_group(p4v1::Update::MODIFY, group);
  }

  DeviceMgr::Status delete_group(p4v1::ActionProfileGroup *group) {
    return write_group(p4v1::Update::DELETE, group);
  }
};

TEST_P(ActionProfTest, Member) {
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
  EXPECT_OK(create_member(&member_1));
  auto mbr_h_1 = mock->get_action_prof_handle();

  // modify member
  member_1 = make_member(member_id_1, adata_2);
  EXPECT_CALL(*mock, action_prof_member_modify(
      act_prof_id, mbr_h_1, ad_matcher_2));
  EXPECT_OK(modify_member(&member_1));

  // add another member
  auto member_2 = make_member(member_id_2, adata_2);
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, ad_matcher_2, _));
  EXPECT_OK(create_member(&member_2));
  auto mbr_h_2 = mock->get_action_prof_handle();
  ASSERT_NE(mbr_h_1, mbr_h_2);

  // delete both members
  EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, mbr_h_1));
  EXPECT_OK(delete_member(&member_1));
  EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, mbr_h_2));
  EXPECT_OK(delete_member(&member_2));
}

TEST_P(ActionProfTest, CreateDupMemberId) {
  DeviceMgr::Status status;
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t member_id = 123;
  std::string adata(6, '\x00');
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _))
      .Times(AtLeast(1));
  auto member = make_member(member_id, adata);
  EXPECT_OK(create_member(&member));
  EXPECT_EQ(create_member(&member), OneExpectedError(Code::ALREADY_EXISTS));
}

TEST_P(ActionProfTest, BadMemberId) {
  DeviceMgr::Status status;
  uint32_t member_id = 123;
  std::string adata(6, '\x00');
  // in this test we do not expect any call to a mock method
  auto member = make_member(member_id, adata);
  // try to modify a member id which does not exist
  EXPECT_EQ(modify_member(&member), OneExpectedError(Code::NOT_FOUND));
  // try to delete a member id which does not exist
  EXPECT_EQ(delete_member(&member), OneExpectedError(Code::NOT_FOUND));
}

TEST_P(ActionProfTest, Group) {
  DeviceMgr::Status status;
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t group_id = 1000;
  uint32_t member_id_1 = 1, member_id_2 = 2;

  // create 2 members
  std::string adata(6, '\x00');
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _))
      .Times(2);
  auto member_1 = make_member(member_id_1, adata);
  EXPECT_OK(create_member(&member_1));
  auto mbr_h_1 = mock->get_action_prof_handle();
  auto member_2 = make_member(member_id_2, adata);
  EXPECT_OK(create_member(&member_2));
  auto mbr_h_2 = mock->get_action_prof_handle();

  // create group with one member
  auto group = make_group(group_id);
  add_member_to_group(&group, member_id_1);
  EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _));
  if (GetParam() == PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
    EXPECT_CALL_GROUP_ADD_MEMBER(*mock, act_prof_id, _, mbr_h_1);
  } else {
    EXPECT_CALL_GROUP_SET_MEMBERS(*mock, act_prof_id, _, _, _)
      .With(Args<3, 2>(ElementsAre(mbr_h_1)));
  }
  ASSERT_OK(create_group(&group));
  auto grp_h = mock->get_action_prof_handle();

  // add the same member
  //   * expect no call when using individual add / remove
  //   * expect same call when using set membership
  EXPECT_NO_CALL_GROUP_ADD_MEMBER(*mock);
  if (GetParam() != PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
    EXPECT_CALL_GROUP_SET_MEMBERS(*mock, act_prof_id, _, _, _)
        .With(Args<3, 2>(ElementsAre(mbr_h_1)));
  }
  ASSERT_OK(modify_group(&group));

  // add a second member
  add_member_to_group(&group, member_id_2);
  if (GetParam() == PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
  EXPECT_CALL_GROUP_ADD_MEMBER(*mock, act_prof_id, grp_h, mbr_h_2);
  } else {
    EXPECT_CALL_GROUP_SET_MEMBERS(*mock, act_prof_id, _, _, _)
        .With(Args<3, 2>(ElementsAre(mbr_h_1, mbr_h_2)));
  }
  ASSERT_OK(modify_group(&group));

  // remove one member
  group.clear_members();
  add_member_to_group(&group, member_id_2);
  if (GetParam() == PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
    EXPECT_CALL_GROUP_REMOVE_MEMBER(*mock, act_prof_id, grp_h, mbr_h_1);
  } else {
    EXPECT_CALL_GROUP_SET_MEMBERS(*mock, act_prof_id, _, _, _)
        .With(Args<3, 2>(ElementsAre(mbr_h_2)));
  }
  ASSERT_OK(modify_group(&group));

  // delete group, which has one remaining member
  group.clear_members();  // not needed
  EXPECT_CALL(*mock, action_prof_group_delete(act_prof_id, grp_h));
  // we do not expect a call to remove_member or set_members, the target is
  // supposed to be able to handle removing non-empty groups
  EXPECT_NO_CALL_GROUP_REMOVE_MEMBER(*mock);
  EXPECT_NO_CALL_GROUP_SET_MEMBERS(*mock);
  ASSERT_OK(delete_group(&group));
}

TEST_P(ActionProfTest, Read) {
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t group_id = 1000;
  uint32_t member_id_1 = 1;

  // create 1 member
  std::string adata(6, '\x00');
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _));
  auto member_1 = make_member(member_id_1, adata);
  EXPECT_OK(create_member(&member_1));

  auto mbr_h_1 = mock->get_action_prof_handle();

  // create group with one member
  auto group = make_group(group_id);
  add_member_to_group(&group, member_id_1);
  EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _));
  if (GetParam() == PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
    EXPECT_CALL_GROUP_ADD_MEMBER(*mock, act_prof_id, _, mbr_h_1);
  } else {
    EXPECT_CALL_GROUP_SET_MEMBERS(*mock, act_prof_id, _, _, _)
        .With(Args<3, 2>(ElementsAre(mbr_h_1)));
  }
  ASSERT_OK(create_group(&group));

  EXPECT_CALL(*mock, action_prof_entries_fetch(act_prof_id, _)).Times(2);
  p4v1::ReadResponse response;
  p4v1::ReadRequest request;
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
  ASSERT_OK(mgr.read(request, &response));
  const auto &entities = response.entities();
  ASSERT_EQ(2, entities.size());
  ASSERT_TRUE(MessageDifferencer::Equals(
      member_1, entities.Get(0).action_profile_member()));
}

TEST_P(ActionProfTest, CreateDupGroupId) {
  DeviceMgr::Status status;
  auto act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  uint32_t group_id = 1000;
  auto group = make_group(group_id);
  EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _))
      .Times(AtLeast(1));
  if (GetParam() != PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
    EXPECT_CALL_GROUP_SET_MEMBERS(*mock, act_prof_id, _, 0, _);
  }
  EXPECT_OK(create_group(&group));
  EXPECT_EQ(create_group(&group), OneExpectedError(Code::ALREADY_EXISTS));
}

TEST_P(ActionProfTest, BadGroupId) {
  DeviceMgr::Status status;
  uint32_t group_id = 1000;
  auto group = make_group(group_id);
  // in this test we do not expect any call to a mock method
  // try to modify a group id which does not exist
  EXPECT_EQ(modify_group(&group), OneExpectedError(Code::NOT_FOUND));
  // try to delete a group id which does not exist
  EXPECT_EQ(delete_group(&group), OneExpectedError(Code::NOT_FOUND));
}

TEST_P(ActionProfTest, AddBadMemberIdToGroup) {
  DeviceMgr::Status status;
  uint32_t group_id = 1000;
  uint32_t bad_member_id = 123;
  auto group = make_group(group_id);
  add_member_to_group(&group, bad_member_id);
  EXPECT_CALL(*mock, action_prof_group_create(_, _, _));
  EXPECT_NO_CALL_GROUP_ADD_MEMBER(*mock);
  EXPECT_NO_CALL_GROUP_SET_MEMBERS(*mock);
  EXPECT_EQ(create_group(&group), OneExpectedError(Code::NOT_FOUND));
}

TEST_P(ActionProfTest, InvalidMemberWeight) {
  DeviceMgr::Status status;
  uint32_t group_id = 1000;
  uint32_t member_id = 1;

  // create 1 member
  std::string adata(6, '\x00');
  EXPECT_CALL(*mock, action_prof_member_create(_, _, _));
  auto member = make_member(member_id, adata);
  EXPECT_OK(create_member(&member));

  EXPECT_CALL(*mock, action_prof_group_create(_, _, _));
  EXPECT_NO_CALL_GROUP_ADD_MEMBER(*mock);
  EXPECT_NO_CALL_GROUP_SET_MEMBERS(*mock);
  auto group = make_group(group_id);
  add_member_to_group(&group, member_id, 0);
  EXPECT_EQ(
      create_group(&group),
      OneExpectedError(Code::INVALID_ARGUMENT,
                       "weight must be a positive integer value"));
}

TEST_P(ActionProfTest, UnsupportedMemberWeight) {
  DeviceMgr::Status status;
  uint32_t group_id = 1000;
  uint32_t member_id = 1;

  // create 1 member
  std::string adata(6, '\x00');
  EXPECT_CALL(*mock, action_prof_member_create(_, _, _));
  auto member = make_member(member_id, adata);
  EXPECT_OK(create_member(&member));

  EXPECT_CALL(*mock, action_prof_group_create(_, _, _));
  EXPECT_NO_CALL_GROUP_ADD_MEMBER(*mock);
  EXPECT_NO_CALL_GROUP_SET_MEMBERS(*mock);
  auto group = make_group(group_id);
  add_member_to_group(&group, member_id, 2);
  EXPECT_EQ(create_group(&group), OneExpectedError(Code::UNIMPLEMENTED));
}

TEST_P(ActionProfTest, InvalidActionProfId) {
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
    p4v1::ReadResponse response;
    p4v1::Entity entity;
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

TEST_P(ActionProfTest, InvalidActionId) {
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

INSTANTIATE_TEST_CASE_P(
    ActionProfPiApis, ActionProfTest,
    Values(PiActProfApiSupport_SET_MBRS,
           PiActProfApiSupport_ADD_AND_REMOVE_MBR,
           PiActProfApiSupport_BOTH));


class MatchTableIndirectTest
    : public DeviceMgrTest, public WithParamInterface<PiActProfApiSupport> {
 protected:
  // a constructor that doesn't use GetParam()
  // This is meant as a convenience for subclasses that do no want to be
  // value-parameterized (and use TEST_F instead of TEST_P).
  explicit MatchTableIndirectTest(PiActProfApiSupport choice) {
    action_prof_api_choice = choice;
    t_id = pi_p4info_table_id_from_name(p4info, "IndirectWS");
    act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  }

  MatchTableIndirectTest() : MatchTableIndirectTest(GetParam()) { }

  void set_action(p4v1::Action *action, const std::string &param_v) {
    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(
        pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
    param->set_value(param_v);
  }

  p4v1::ActionProfileMember make_member(uint32_t member_id,
                                        const std::string &param_v = "") {
    p4v1::ActionProfileMember member;
    member.set_action_profile_id(act_prof_id);
    member.set_member_id(member_id);
    set_action(member.mutable_action(), param_v);
    return member;
  }

  void create_member(uint32_t member_id, const std::string &param_v) {
    EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _));
    auto member = make_member(member_id, param_v);
    p4v1::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4v1::Update::INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_member(&member);
    auto status = mgr.write(request);
    entity->release_action_profile_member();
    EXPECT_EQ(status.code(), Code::OK);
  }

  template <typename It>
  p4v1::ActionProfileGroup make_group(uint32_t group_id,
                                      It members_begin, It members_end) {
    p4v1::ActionProfileGroup group;
    group.set_action_profile_id(act_prof_id);
    group.set_group_id(group_id);
    for (auto it = members_begin; it != members_end; ++it) {
      auto member = group.add_members();
      member->set_member_id(*it);
      member->set_weight(1);
    }
    return group;
  }

  // create a group which includes the provided members
  template <typename It>
  void create_group(uint32_t group_id, It members_begin, It members_end) {
    EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, _, _));
    if (GetParam() == PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
      EXPECT_CALL_GROUP_ADD_MEMBER(*mock, act_prof_id, _, _)
          .Times(std::distance(members_begin, members_end));
    } else {
      EXPECT_CALL_GROUP_SET_MEMBERS(
          *mock, act_prof_id, _, std::distance(members_begin, members_end), _);
    }
    auto group = make_group(group_id, members_begin, members_end);
    p4v1::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4v1::Update::INSERT);
    auto entity = update->mutable_entity();
    entity->set_allocated_action_profile_group(&group);
    auto status = mgr.write(request);
    entity->release_action_profile_group();
    EXPECT_OK(status);
  }

  void create_group(uint32_t group_id, uint32_t member_id) {
    create_group(group_id, &member_id, (&member_id) + 1);
  }

  p4v1::TableEntry make_indirect_entry_to_member(const std::string &mf_v,
                                                 uint32_t member_id) {
    return make_indirect_entry_common(mf_v, member_id, false);
  }

  p4v1::TableEntry make_indirect_entry_to_group(const std::string &mf_v,
                                                uint32_t group_id) {
    return make_indirect_entry_common(mf_v, group_id, true);
  }

  template <typename It>
  p4v1::TableEntry make_indirect_entry_one_shot(
      const boost::optional<std::string> &mf_v,
      It params_begin, It params_end,
      int weight = 1) {
    p4v1::TableEntry table_entry;
    auto t_id = pi_p4info_table_id_from_name(p4info, "IndirectWS");
    table_entry.set_table_id(t_id);
    if (mf_v.is_initialized()) {
      auto mf = table_entry.add_match();
      mf->set_field_id(pi_p4info_table_match_field_id_from_name(
          p4info, t_id, "header_test.field32"));
      auto mf_exact = mf->mutable_exact();
      mf_exact->set_value(*mf_v);
    }
    auto entry = table_entry.mutable_action();
    auto ap_action_set = entry->mutable_action_profile_action_set();
    for (auto param_it = params_begin; param_it != params_end; param_it++) {
      auto ap_action = ap_action_set->add_action_profile_actions();
      set_action(ap_action->mutable_action(), *param_it);
      ap_action->set_weight(weight);
    }
    return table_entry;
  }

  template <typename It>
  DeviceMgr::Status add_indirect_entry_one_shot(
      p4v1::TableEntry *entry, It params_begin, It params_end) {
    for (auto param_it = params_begin; param_it != params_end; param_it++) {
      auto ad_matcher = CorrectActionData(a_id, *param_it);
      EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, ad_matcher, _));
    }
    auto params_size = static_cast<size_t>(
        std::distance(params_begin, params_end));
    EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, params_size, _));
    if (GetParam() == PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
      EXPECT_CALL_GROUP_ADD_MEMBER(*mock, act_prof_id, _, _).Times(params_size);
    } else {
      EXPECT_CALL_GROUP_SET_MEMBERS(*mock, act_prof_id, _, params_size, _);
    }
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    return add_entry(entry);
  }

  pi_p4_id_t t_id;
  pi_p4_id_t act_prof_id;
  pi_p4_id_t a_id;

 private:
  p4v1::TableEntry make_indirect_entry_common(const std::string &mf_v,
                                              uint32_t indirect_id,
                                              bool is_group) {
    p4v1::TableEntry table_entry;
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

TEST_P(MatchTableIndirectTest, Member) {
  uint32_t member_id = 123;
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  create_member(member_id, adata);
  auto mbr_h = mock->get_action_prof_handle();
  auto mk_matcher = CorrectMatchKey(t_id, mf);
  auto entry_matcher = CorrectTableEntryIndirect(mbr_h);
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, entry_matcher, _));
  auto entry = make_indirect_entry_to_member(mf, member_id);
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  p4v1::ReadResponse response;
  p4v1::Entity entity;
  auto table_entry = entity.mutable_table_entry();
  table_entry->set_table_id(t_id);
  status = mgr.read_one(entity, &response);
  ASSERT_EQ(status.code(), Code::OK);
  const auto &entities = response.entities();
  ASSERT_EQ(1, entities.size());
  ASSERT_TRUE(MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
}

TEST_P(MatchTableIndirectTest, Group) {
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
  auto status = add_entry(&entry);
  ASSERT_EQ(status.code(), Code::OK);

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  p4v1::ReadResponse response;
  p4v1::Entity entity;
  auto table_entry = entity.mutable_table_entry();
  table_entry->set_table_id(t_id);
  status = mgr.read_one(entity, &response);
  ASSERT_EQ(status.code(), Code::OK);
  const auto &entities = response.entities();
  ASSERT_EQ(1, entities.size());
  ASSERT_TRUE(MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
}

TEST_P(MatchTableIndirectTest, OneShotInsertAndRead) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::vector<std::string> params;
  params.emplace_back(6, '\x00');
  params.emplace_back(6, '\x01');
  auto entry = make_indirect_entry_one_shot(mf, params.begin(), params.end());
  ASSERT_OK(add_indirect_entry_one_shot(&entry, params.begin(), params.end()));

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _));
  EXPECT_CALL(*mock, action_prof_entries_fetch(act_prof_id, _));

  p4v1::ReadResponse response;
  ASSERT_OK(read_table_entries(t_id, &response));
  const auto &entities = response.entities();
  ASSERT_EQ(1, entities.size());
  EXPECT_TRUE(
      MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
}

TEST_P(MatchTableIndirectTest, OneShotInsertAndModify) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::vector<std::string> params;
  params.emplace_back(6, '\x00');
  params.emplace_back(6, '\x01');
  auto entry_1 = make_indirect_entry_one_shot(mf, params.begin(), params.end());
  ASSERT_OK(add_indirect_entry_one_shot(
      &entry_1, params.begin(), params.end()));

  EXPECT_CALL(*mock, action_prof_group_delete(act_prof_id, _));
  EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, _))
      .Times(params.size());

  params.pop_back();
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _))
      .Times(params.size());
  EXPECT_CALL(*mock, action_prof_group_create(act_prof_id, params.size(), _));
  if (GetParam() == PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
    EXPECT_CALL_GROUP_ADD_MEMBER(*mock, act_prof_id, _, _).Times(params.size());
  } else {
    EXPECT_CALL_GROUP_SET_MEMBERS(*mock, act_prof_id, _, params.size(), _);
  }
  EXPECT_CALL(*mock, table_entry_modify_wkey(t_id, _, _));

  auto entry_2 = make_indirect_entry_one_shot(mf, params.begin(), params.end());
  EXPECT_OK(modify_entry(&entry_2));
}

TEST_P(MatchTableIndirectTest, OneShotInsertAndDelete) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::vector<std::string> params;
  params.emplace_back(6, '\x00');
  params.emplace_back(6, '\x01');
  auto entry = make_indirect_entry_one_shot(mf, params.begin(), params.end());
  ASSERT_OK(add_indirect_entry_one_shot(&entry, params.begin(), params.end()));

  EXPECT_CALL(*mock, action_prof_group_delete(act_prof_id, _));
  EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, _))
      .Times(params.size());
  EXPECT_CALL(*mock, table_entry_delete_wkey(t_id, _));

  EXPECT_OK(remove_entry(&entry));
}

TEST_P(MatchTableIndirectTest, OneShotInvalidActionWeight) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::vector<std::string> params;
  params.emplace_back(6, '\x00');
  params.emplace_back(6, '\x01');
  auto entry =
      make_indirect_entry_one_shot(mf, params.begin(), params.end(), 0);
  EXPECT_EQ(
      add_entry(&entry),
      OneExpectedError(Code::INVALID_ARGUMENT,
                       "weight must be a positive integer value"));
}

TEST_P(MatchTableIndirectTest, OneShotUnsupportedActionWeight) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::vector<std::string> params;
  params.emplace_back(6, '\x00');
  params.emplace_back(6, '\x01');
  auto entry =
      make_indirect_entry_one_shot(mf, params.begin(), params.end(), 2);
  EXPECT_EQ(add_entry(&entry), OneExpectedError(Code::UNIMPLEMENTED));
}

TEST_P(MatchTableIndirectTest, MixedSelectorModes) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  std::vector<std::string> params({adata});
  auto entry = make_indirect_entry_one_shot(mf, params.begin(), params.end());
  ASSERT_OK(add_indirect_entry_one_shot(&entry, params.begin(), params.end()));

  uint32_t member_id = 123;
  auto member = make_member(member_id, adata);
  p4v1::WriteRequest request;
  {
    auto update = request.add_updates();
    update->set_type(p4v1::Update::INSERT);
    update->mutable_entity()->mutable_action_profile_member()->CopyFrom(member);
  }

  // the selector is now in ONESHOT mode, trying to use it in MANUAL mode should
  // trigger an error
  ASSERT_EQ(mgr.write(request), OneExpectedError(Code::INVALID_ARGUMENT));

  // if we empty the selector we should be able to use MANUAL mode
  EXPECT_CALL(*mock, action_prof_group_delete(act_prof_id, _));
  EXPECT_CALL(*mock, action_prof_member_delete(act_prof_id, _))
      .Times(params.size());
  EXPECT_CALL(*mock, table_entry_delete_wkey(t_id, _));
  ASSERT_OK(remove_entry(&entry));
  EXPECT_CALL(*mock, action_prof_member_create(act_prof_id, _, _));
  ASSERT_OK(mgr.write(request));

  // the selector is now in MANUAL mode, trying to use it in ONESHOT mode should
  // trigger an error
  ASSERT_EQ(add_entry(&entry), OneExpectedError(Code::INVALID_ARGUMENT));
}

TEST_P(MatchTableIndirectTest, SetDefault) {
  std::vector<std::string> params;
  params.emplace_back(6, '\x00');
  params.emplace_back(6, '\x01');
  auto entry = make_indirect_entry_one_shot(
      boost::none /* no match */, params.begin(), params.end());
  entry.set_is_default_action(true);
  // Cannot set default entry for indirect table
  EXPECT_EQ(
      modify_entry(&entry),
      OneExpectedError(Code::INVALID_ARGUMENT,
                       "Cannot set / reset default action for indirect table"));
}

INSTANTIATE_TEST_CASE_P(
    ActionProfPiApis, MatchTableIndirectTest,
    Values(PiActProfApiSupport_SET_MBRS,
           PiActProfApiSupport_ADD_AND_REMOVE_MBR,
           PiActProfApiSupport_BOTH));


class ExactOneTest : public DeviceMgrTest {
 protected:
  ExactOneTest(const std::string &t_name, const std::string &f_name)
      : f_name(f_name) {
    t_id = pi_p4info_table_id_from_name(p4info, t_name.c_str());
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  }

  ExactOneTest()
      : ExactOneTest("ExactOne", "header_test.field32") { }

  p4v1::TableEntry make_entry(const boost::optional<std::string> &mf_v,
                              const std::string &param_v) {
    p4v1::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    if (mf_v.is_initialized()) {
      auto mf = table_entry.add_match();
      mf->set_field_id(pi_p4info_table_match_field_id_from_name(
          p4info, t_id, f_name.c_str()));
      auto mf_exact = mf->mutable_exact();
      mf_exact->set_value(*mf_v);
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

TEST_F(ExactOneTest, PriorityForNonTernaryMatch) {
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  int priority(789);
  auto entry = make_entry(mf, adata);
  entry.set_priority(priority);
  auto status = add_entry(&entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

// There used to be an issue where the MatchKey instance for the default entry
// and the MatchKey instance for an entry whose match key was zero'd-out were
// equal (DeviceMgr handles all match entries uniformly in the table
// store). This means that this test was failing with an ALREADY_EXISTS error
// code.
TEST_F(ExactOneTest, ZeroKeyAndDefaultEntry) {
  std::string mf(4, '\x00');
  std::string adata(6, '\x00');
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
  EXPECT_CALL(*mock, table_default_action_set(t_id, _)).Times(2);
  {
    auto entry = make_entry(boost::none, adata);
    entry.set_is_default_action(true);
    auto status = modify_entry(&entry);
    EXPECT_EQ(status.code(), Code::OK);
  }
  {
    auto entry = make_entry(mf, adata);
    auto status = add_entry(&entry);
    EXPECT_EQ(status.code(), Code::OK);
  }
  {
    auto entry = make_entry(boost::none, adata);
    entry.set_is_default_action(true);
    auto status = modify_entry(&entry);
    EXPECT_EQ(status.code(), Code::OK);
  }
}


class DirectMeterTest : public ExactOneTest {
 protected:
  DirectMeterTest()
      : ExactOneTest("ExactOne", "header_test.field32") {
    m_id = pi_p4info_meter_id_from_name(p4info, "ExactOne_meter");
  }

  DeviceMgr::Status set_meter(p4v1::DirectMeterEntry *direct_meter_entry) {
    p4v1::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4v1::Update::MODIFY);
    auto entity = update->mutable_entity();
    entity->set_allocated_direct_meter_entry(direct_meter_entry);
    auto status = mgr.write(request);
    entity->release_direct_meter_entry();
    return status;
  }

  p4v1::DirectMeterEntry make_meter_entry(const p4v1::TableEntry &entry,
                                          const p4v1::MeterConfig &config) {
    p4v1::DirectMeterEntry direct_meter_entry;
    direct_meter_entry.mutable_table_entry()->CopyFrom(entry);
    direct_meter_entry.mutable_config()->CopyFrom(config);
    return direct_meter_entry;
  }

  p4v1::MeterConfig make_meter_config() const {
    p4v1::MeterConfig config;
    config.set_cir(10);
    config.set_cburst(5);
    config.set_pir(100);
    config.set_pburst(250);
    return config;
  }

  DeviceMgr::Status read_meter(p4v1::DirectMeterEntry *direct_meter_entry,
                               p4v1::ReadResponse *response) {
    p4v1::ReadRequest request;
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
    p4v1::ReadResponse response;
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
    p4v1::ReadResponse response;
    p4v1::Entity entity;
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
  p4v1::DirectMeterEntry meter_entry;
  auto status = set_meter(&meter_entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

class IndirectMeterTest : public DeviceMgrTest  {
 protected:
  IndirectMeterTest() {
    m_id = pi_p4info_meter_id_from_name(p4info, "MeterA");
    m_size = pi_p4info_meter_get_size(p4info, m_id);
  }

  DeviceMgr::Status read_meter(p4v1::MeterEntry *meter_entry,
                               p4v1::ReadResponse *response) {
    p4v1::ReadRequest request;
    auto entity = request.add_entities();
    entity->set_allocated_meter_entry(meter_entry);
    auto status = mgr.read(request, response);
    entity->release_meter_entry();
    return status;
  }

  DeviceMgr::Status write_meter(p4v1::MeterEntry *meter_entry) {
    p4v1::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4v1::Update::MODIFY);
    auto entity = update->mutable_entity();
    entity->set_allocated_meter_entry(meter_entry);
    auto status = mgr.write(request);
    entity->release_meter_entry();
    return status;
  }

  p4v1::MeterConfig make_meter_config() const {
    p4v1::MeterConfig config;
    config.set_cir(10);
    config.set_cburst(5);
    config.set_pir(100);
    config.set_pburst(250);
    return config;
  }

  void set_index(p4v1::MeterEntry *meter_entry, int index) const {
    auto *index_msg = meter_entry->mutable_index();
    index_msg->set_index(index);
  }

  pi_p4_id_t m_id{0};
  size_t m_size{0};
};

TEST_F(IndirectMeterTest, WriteAndRead) {
  int index = 66;
  p4v1::ReadResponse response;
  p4v1::MeterEntry meter_entry;
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
  DeviceMgr::Status read_counter(p4v1::DirectCounterEntry *direct_counter_entry,
                                 p4v1::ReadResponse *response) {
    p4v1::ReadRequest request;
    auto entity = request.add_entities();
    entity->set_allocated_direct_counter_entry(direct_counter_entry);
    auto status = mgr.read(request, response);
    entity->release_direct_counter_entry();
    return status;
  }

  DeviceMgr::Status write_counter(
      p4v1::DirectCounterEntry *direct_counter_entry) {
    p4v1::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4v1::Update::MODIFY);
    auto entity = update->mutable_entity();
    entity->set_allocated_direct_counter_entry(direct_counter_entry);
    auto status = mgr.write(request);
    entity->release_direct_counter_entry();
    return status;
  }

  p4v1::DirectCounterEntry make_counter_entry(const p4v1::TableEntry *entry) {
    p4v1::DirectCounterEntry direct_counter_entry;
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
    p4v1::ReadResponse response;
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
    p4v1::ReadResponse response;
    p4v1::Entity entity;
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
    p4v1::ReadResponse response;
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

  p4v1::ReadResponse response;
  p4v1::DirectCounterEntry counter_entry;
  counter_entry.mutable_table_entry()->set_table_id(entry.table_id());
  auto status = read_counter(&counter_entry, &response);
  ASSERT_EQ(status.code(), Code::UNIMPLEMENTED);
}

TEST_F(DirectCounterTest, MissingTableEntry) {
  p4v1::ReadResponse response;
  p4v1::DirectCounterEntry counter_entry;
  auto status = read_counter(&counter_entry, &response);
  EXPECT_EQ(status.code(), Code::INVALID_ARGUMENT);
}

// TODO(antonin)
TEST_F(DirectCounterTest, ReadAll) {
  p4v1::ReadResponse response;
  p4v1::DirectCounterEntry counter_entry;
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
  DeviceMgr::Status read_counter(p4v1::CounterEntry *counter_entry,
                                 p4v1::ReadResponse *response) {
    p4v1::ReadRequest request;
    auto entity = request.add_entities();
    entity->set_allocated_counter_entry(counter_entry);
    auto status = mgr.read(request, response);
    entity->release_counter_entry();
    return status;
  }

  DeviceMgr::Status write_counter(p4v1::CounterEntry *counter_entry) {
    p4v1::WriteRequest request;
    auto update = request.add_updates();
    update->set_type(p4v1::Update::MODIFY);
    auto entity = update->mutable_entity();
    entity->set_allocated_counter_entry(counter_entry);
    auto status = mgr.write(request);
    entity->release_counter_entry();
    return status;
  }

  void set_index(p4v1::CounterEntry *counter_entry, int index) const {
    auto *index_msg = counter_entry->mutable_index();
    index_msg->set_index(index);
  }

  pi_p4_id_t c_id{0};
  size_t c_size{0};
};

TEST_F(IndirectCounterTest, WriteAndRead) {
  int index = 66;
  p4v1::ReadResponse response;
  p4v1::CounterEntry counter_entry;
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
  p4v1::ReadResponse response;
  p4v1::CounterEntry counter_entry;
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

  p4v1::TableEntry make_entry_no_mk() {
    p4v1::TableEntry table_entry;
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

  void add_one_mf(p4v1::TableEntry *entry, const std::string &mf_v) {
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

  p4v1::TableEntry make_entry(const boost::optional<std::string> &mf_v,
                              const boost::optional<std::string> &mask_v,
                              const std::string &param_v,
                              int priority = PRIORITY) {
    p4v1::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    table_entry.set_priority(priority);
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

    p4v1::ReadResponse response;
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

TEST_F(TernaryOneTest, ZeroPriority) {
  std::string adata(6, '\x00');
  auto entry = make_entry(boost::none, boost::none, adata, 0);
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(0);
  auto status = add_entry(&entry);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
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

  p4v1::TableEntry make_entry(const boost::optional<std::string> &low_v,
                            const boost::optional<std::string> &high_v,
                            const std::string &param_v) {
    p4v1::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    table_entry.set_priority(PRIORITY);
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

    p4v1::ReadResponse response;
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

  p4v1::TableEntry make_entry(const boost::optional<std::string> &mf_v,
                              int pLen,
                              const std::string &param_v) {
    p4v1::TableEntry table_entry;
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

    p4v1::ReadResponse response;
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

  p4v1::TableEntry make_entry(const std::string &mf1_v,
                              const std::string &mask1_v,
                              const std::string &mf2_v,
                              const std::string &mask2_v,
                              const std::string &param_v) {
    p4v1::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    table_entry.set_priority(PRIORITY);
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


template <typename Entry,
          Entry *(::p4v1::PacketReplicationEngineEntry::*Accessor)()>
class PRETestBase : public DeviceMgrTest {
 protected:
  DeviceMgr::Status create_entry(const Entry &entry) {
    return write_entry(entry, p4v1::Update::INSERT);
  }

  DeviceMgr::Status modify_entry(const Entry &entry) {
    return write_entry(entry, p4v1::Update::MODIFY);
  }

  DeviceMgr::Status delete_entry(const Entry &entry) {
    return write_entry(entry, p4v1::Update::DELETE);
  }

  struct ReplicaMgr {
    explicit ReplicaMgr(Entry *entry)
        : entry(entry) { }

    ReplicaMgr &push_back(int32_t port, int32_t rid) {
      auto r = entry->add_replicas();
      r->set_egress_port(port);
      r->set_instance(rid);
      return *this;
    }

    void pop_back() {
      entry->mutable_replicas()->RemoveLast();
    }

    Entry *entry;
  };

 private:
  DeviceMgr::Status write_entry(const Entry &entry, p4v1::Update::Type type) {
    p4v1::WriteRequest request;
    auto *update = request.add_updates();
    update->set_type(type);
    auto *entity = update->mutable_entity();
    auto *pre_entry = entity->mutable_packet_replication_engine_entry();
    (pre_entry->*Accessor)()->CopyFrom(entry);
    return mgr.write(request);
  }
};

class PREMulticastTest : public PRETestBase<
  ::p4v1::MulticastGroupEntry,
  &::p4v1::PacketReplicationEngineEntry::mutable_multicast_group_entry> {
 protected:
  using GroupEntry = ::p4v1::MulticastGroupEntry;

  DeviceMgr::Status create_group(const GroupEntry &group) {
    return create_entry(group);
  }

  DeviceMgr::Status modify_group(const GroupEntry &group) {
    return modify_entry(group);
  }

  DeviceMgr::Status delete_group(const GroupEntry &group) {
    return delete_entry(group);
  }
};

TEST_F(PREMulticastTest, Write) {
  int32_t group_id = 66;
  GroupEntry group;
  group.set_multicast_group_id(group_id);
  int32_t port1 = 1, rid1 = 1, port2 = 2, rid2 = 2;
  ReplicaMgr replicas(&group);
  replicas.push_back(port1, rid1).push_back(port2, rid2);
  EXPECT_CALL(*mock, mc_grp_create(group_id, _));
  // need a more complicated matcher because of the C array. The ElementsAre
  // matcher can be used but required 2 arguments (the pointer + count, in this
  // order)
  EXPECT_CALL(*mock, mc_node_create(rid1, _, _, _))
      .With(Args<2, 1>(ElementsAre(port1)));
  EXPECT_CALL(*mock, mc_node_create(rid2, _, _, _))
      .With(Args<2, 1>(ElementsAre(port2)));
  EXPECT_CALL(*mock, mc_grp_attach_node(_, _)).Times(2);
  {
    auto status = create_group(group);
    ASSERT_EQ(status.code(), Code::OK);
  }
  auto grp_h = mock->get_mc_grp_handle();

  int32_t port3 = 3, rid3 = rid1, port4 = 4, rid4 = 4;
  replicas.push_back(port3, rid3).push_back(port4, rid4);
  EXPECT_CALL(*mock, mc_node_modify(_, _, _))
      .With(Args<2, 1>(ElementsAre(port1, port3)));
  EXPECT_CALL(*mock, mc_node_create(rid4, _, _, _))
      .With(Args<2, 1>(ElementsAre(port4)));
  EXPECT_CALL(*mock, mc_grp_attach_node(grp_h, _));
  {
    auto status = modify_group(group);
    ASSERT_EQ(status.code(), Code::OK);
  }
  auto node_h = mock->get_mc_node_handle();  // rid4

  replicas.pop_back();
  EXPECT_CALL(*mock, mc_grp_detach_node(grp_h, node_h));
  EXPECT_CALL(*mock, mc_node_delete(node_h));
  {
    auto status = modify_group(group);
    ASSERT_EQ(status.code(), Code::OK);
  }

  EXPECT_CALL(*mock, mc_grp_detach_node(grp_h, _)).Times(2);
  EXPECT_CALL(*mock, mc_node_delete(_)).Times(2);
  EXPECT_CALL(*mock, mc_grp_delete(grp_h));
  {
    auto status = delete_group(group);
    ASSERT_EQ(status.code(), Code::OK);
  }
}

TEST_F(PREMulticastTest, Duplicates) {
  int32_t group_id = 66;
  GroupEntry group;
  group.set_multicast_group_id(group_id);
  int32_t port1 = 1, rid1 = 1, port2 = port1, rid2 = rid1;
  ReplicaMgr replicas(&group);;
  replicas.push_back(port1, rid1).push_back(port2, rid2);
  auto status = create_group(group);
  EXPECT_EQ(status, OneExpectedError(Code::INVALID_ARGUMENT));
}

TEST_F(PREMulticastTest, Read) {
  p4v1::ReadRequest request;
  p4v1::ReadResponse response;
  auto *entity = request.add_entities();
  // set oneof to PRE
  entity->mutable_packet_replication_engine_entry();

  auto status = mgr.read(request, &response);
  EXPECT_EQ(status.code(), Code::UNIMPLEMENTED);
}

class PRECloningTest : public PRETestBase<
  ::p4v1::CloneSessionEntry,
  &::p4v1::PacketReplicationEngineEntry::mutable_clone_session_entry> {
 protected:
  using SessionEntry = ::p4v1::CloneSessionEntry;

  DeviceMgr::Status create_session(const SessionEntry &session) {
    return create_entry(session);
  }

  DeviceMgr::Status modify_session(const SessionEntry &session) {
    return modify_entry(session);
  }

  DeviceMgr::Status delete_session(const SessionEntry &session) {
    return delete_entry(session);
  }
};

TEST_F(PRECloningTest, Write) {
  int32_t session_id = 66;
  SessionEntry session;
  session.set_session_id(session_id);
  int32_t port1 = 1, port2 = 2, rid = 1;
  ReplicaMgr replicas(&session);
  replicas.push_back(port1, rid).push_back(port2, rid);
  EXPECT_CALL(*mock, mc_grp_create(_, _));
  EXPECT_CALL(*mock, mc_node_create(rid, _, _, _))
      .With(Args<2, 1>(ElementsAre(port1, port2)));
  EXPECT_CALL(*mock, mc_grp_attach_node(_, _));
  EXPECT_CALL(
      *mock, clone_session_set(session_id, CorrectCloneSessionConfig(session)));
  {
    auto status = create_session(session);
    ASSERT_EQ(status.code(), Code::OK);
  }
  auto grp_h = mock->get_mc_grp_handle();

  replicas.pop_back();
  EXPECT_CALL(*mock, mc_node_modify(_, _, _))
      .With(Args<2, 1>(ElementsAre(port1)));
  {
    auto status = modify_session(session);
    ASSERT_EQ(status.code(), Code::OK);
  }

  EXPECT_CALL(*mock, mc_grp_detach_node(grp_h, _));
  EXPECT_CALL(*mock, mc_node_delete(_));
  EXPECT_CALL(*mock, mc_grp_delete(grp_h));
  EXPECT_CALL(*mock, clone_session_reset(session_id));
  {
    auto status = delete_session(session);
    ASSERT_EQ(status.code(), Code::OK);
  }
}

TEST_F(PRECloningTest, Read) {
  p4v1::ReadRequest request;
  p4v1::ReadResponse response;
  auto *entity = request.add_entities();
  auto *pre_entry = entity->mutable_packet_replication_engine_entry();
  pre_entry->mutable_clone_session_entry();
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
  p4v1::WriteRequest const_entries_request;
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
  p4v1::ReadResponse response;
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
  p4v1::ReadResponse response;
  auto status = read_table_entries(t_id, &response);
  EXPECT_EQ(status.code(), Code::OK);
}


// Placeholder for PVS (Parser Value Set) tests: for now there is no support in
// DeviceMgr
class PVSTest : public DeviceMgrTest { };

TEST_F(PVSTest, Write) {
  p4v1::WriteRequest request;
  auto *update = request.add_updates();
  update->set_type(p4v1::Update::MODIFY);
  auto *entity = update->mutable_entity();
  auto *pvs_entry = entity->mutable_value_set_entry();
  (void) pvs_entry;
  auto status = mgr.write(request);
  EXPECT_EQ(status, OneExpectedError(Code::UNIMPLEMENTED));
}

TEST_F(PVSTest, Read) {
  p4v1::ReadRequest request;
  p4v1::ReadResponse response;
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
  p4v1::WriteRequest request;
  auto *update = request.add_updates();
  update->set_type(p4v1::Update::MODIFY);
  auto *entity = update->mutable_entity();
  auto *register_entry = entity->mutable_register_entry();
  (void) register_entry;
  auto status = mgr.write(request);
  EXPECT_EQ(status, OneExpectedError(Code::UNIMPLEMENTED));
}

TEST_F(RegisterTest, Read) {
  p4v1::ReadRequest request;
  p4v1::ReadResponse response;
  auto *entity = request.add_entities();
  auto *register_entry = entity->mutable_register_entry();
  (void) register_entry;
  auto status = mgr.read(request, &response);
  EXPECT_EQ(status.code(), Code::UNIMPLEMENTED);
}

// for digest tests, see test_proto_fe_digest.cpp
class DigestTest : public DeviceMgrTest { };

TEST_F(DigestTest, WriteAndRead) {
  auto digest_id = pi_p4info_digest_id_from_name(p4info, "test_digest_t");
  ASSERT_NE(digest_id, 0u);
  p4v1::WriteRequest request;
  auto *update = request.add_updates();
  update->set_type(p4v1::Update::INSERT);
  auto *entity = update->mutable_entity();
  auto *digest_entry = entity->mutable_digest_entry();
  digest_entry->set_digest_id(digest_id);
  digest_entry->mutable_config()->set_max_list_size(100);
  EXPECT_CALL(*mock, learn_config_set(
      digest_id, EqDigestConfig(digest_entry->config())));
  EXPECT_OK(mgr.write(request));
  p4v1::ReadResponse response;
  EXPECT_OK(mgr.read_one(*entity, &response));
  const auto &read_entities = response.entities();
  ASSERT_EQ(read_entities.size(), 1);
  EXPECT_TRUE(MessageDifferencer::Equals(
      *digest_entry, read_entities.Get(0).digest_entry()));
  update->set_type(p4v1::Update::DELETE);
  EXPECT_CALL(*mock, learn_config_set(digest_id, IsNull()));
  EXPECT_OK(mgr.write(request));
}

// This test verifies that the ReadRequest gets a unique lock (no concurrent
// writes).
// We inherit from MatchTableIndirectTest as a convenience (to access all table
// / action profile modifiers).
class ReadExclusiveAccess : public MatchTableIndirectTest {
 public:
  ReadExclusiveAccess()
      : MatchTableIndirectTest(PiActProfApiSupport_ADD_AND_REMOVE_MBR) {
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

    std::vector<p4v1::WriteRequest> requests(4);
    {
      auto &request = requests.at(0);
      auto *update = request.add_updates();
      update->set_type(p4v1::Update::INSERT);
      auto *entity = update->mutable_entity();
      entity->mutable_action_profile_member()->CopyFrom(member);
    }
    {
      auto &request = requests.at(1);
      auto *update = request.add_updates();
      update->set_type(p4v1::Update::INSERT);
      auto *entity = update->mutable_entity();
      entity->mutable_table_entry()->CopyFrom(entry);
    }
    {
      auto &request = requests.at(2);
      auto *update = request.add_updates();
      update->set_type(p4v1::Update::DELETE);
      auto *entity = update->mutable_entity();
      entity->mutable_table_entry()->CopyFrom(entry);
    }
    {
      auto &request = requests.at(3);
      auto *update = request.add_updates();
      update->set_type(p4v1::Update::DELETE);
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
    p4v1::ReadRequest request;
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
      p4v1::ReadResponse response;
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


class MatchTableConstDefaultActionTest : public DeviceMgrTest {
 protected:
  MatchTableConstDefaultActionTest() {
    t_id = pi_p4info_table_id_from_name(p4info, "ConstDefaultActionTable");
    aB_id = pi_p4info_action_id_from_name(p4info, "actionB");
    aC_id = pi_p4info_action_id_from_name(p4info, "actionC");
  }

  DeviceMgr::Status set_default(pi_p4_id_t a_id,
                                const boost::optional<std::string> &param_v) {
    p4v1::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    table_entry.set_is_default_action(true);
    auto entry = table_entry.mutable_action();
    auto action = entry->mutable_action();
    action->set_action_id(a_id);
    if (param_v.is_initialized()) {
      auto param = action->add_params();
      param->set_param_id(
          pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
      param->set_value(*param_v);
    }
    return modify_entry(&table_entry);
  }

  pi_p4_id_t t_id;
  pi_p4_id_t aB_id;  // DEFAULT_ONLY scope, const default action
  pi_p4_id_t aC_id;  // TABLE_AND_DEFAULT scope
};

TEST_F(MatchTableConstDefaultActionTest, MutateParam) {
  EXPECT_EQ(set_default(aB_id, std::string("\xaa")),
            OneExpectedError(Code::PERMISSION_DENIED, "const default action"));
}

TEST_F(MatchTableConstDefaultActionTest, MutateAction) {
  EXPECT_EQ(set_default(aC_id, boost::none),
            OneExpectedError(Code::PERMISSION_DENIED, "const default action"));
}


class MatchTableActionAnnotationsTest : public DeviceMgrTest {
 protected:
  MatchTableActionAnnotationsTest() {
    t_id = pi_p4info_table_id_from_name(p4info, "ActionsAnnotationsTable");
    mf_id = pi_p4info_table_match_field_id_from_name(
        p4info, t_id, "header_test.field16");
    aA_id = pi_p4info_action_id_from_name(p4info, "actionA");
    aB_id = pi_p4info_action_id_from_name(p4info, "actionB");
    aC_id = pi_p4info_action_id_from_name(p4info, "actionC");
  }

  DeviceMgr::Status set_default(pi_p4_id_t a_id,
                                const boost::optional<std::string> &param_v) {
    p4v1::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    table_entry.set_is_default_action(true);
    set_action(&table_entry, a_id, param_v);
    return modify_entry(&table_entry);
  }

  DeviceMgr::Status insert_entry(const std::string &mf_v,
                                 pi_p4_id_t a_id,
                                 const boost::optional<std::string> &param_v) {
    p4v1::TableEntry table_entry;
    table_entry.set_table_id(t_id);
    auto mf = table_entry.add_match();
    mf->set_field_id(mf_id);
    auto mf_exact = mf->mutable_exact();
    mf_exact->set_value(mf_v);
    set_action(&table_entry, a_id, param_v);
    return add_entry(&table_entry);
  }

  pi_p4_id_t t_id;
  pi_p4_id_t mf_id;
  pi_p4_id_t aA_id;  // TABLE_AND_DEFAULT scope
  pi_p4_id_t aB_id;  // TABLE_ONLY scope
  pi_p4_id_t aC_id;  // DEFAULT_ONLY scope

 private:
  void set_action(p4v1::TableEntry *table_entry,
                  pi_p4_id_t a_id,
                  const boost::optional<std::string> &param_v) const {
    auto entry = table_entry->mutable_action();
    auto action = entry->mutable_action();
    action->set_action_id(a_id);
    if (param_v.is_initialized()) {
      auto param = action->add_params();
      param->set_param_id(
          pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
      param->set_value(*param_v);
    }
  }
};

TEST_F(MatchTableActionAnnotationsTest, TableAndDefault) {
  EXPECT_CALL(*mock, table_default_action_set(t_id, _));
  EXPECT_OK(set_default(aA_id, std::string(6, '\xaa')));
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
  EXPECT_OK(insert_entry(
      std::string("\x01\x02"), aA_id, std::string(6, '\xaa')));
}

TEST_F(MatchTableActionAnnotationsTest, TableOnly) {
  EXPECT_CALL(*mock, table_default_action_set(t_id, _)).Times(Exactly(0));
  EXPECT_EQ(set_default(aB_id, std::string("\xaa")),
            OneExpectedError(Code::PERMISSION_DENIED,
                             "Cannot use TABLE_ONLY action as default action"));
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
  EXPECT_OK(insert_entry(std::string("\x01\x02"), aB_id, std::string("\xaa")));
}

TEST_F(MatchTableActionAnnotationsTest, DefaultOnly) {
  EXPECT_CALL(*mock, table_default_action_set(t_id, _));
  EXPECT_OK(set_default(aC_id, boost::none));
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(Exactly(0));
  EXPECT_EQ(insert_entry(std::string("\x01\x02"), aC_id, boost::none),
            OneExpectedError(Code::PERMISSION_DENIED,
                             "Cannot use DEFAULT_ONLY action in table entry"));
}


class IdleTimeoutTest : public ExactOneTest {
 protected:
  IdleTimeoutTest()
      : ExactOneTest("IdleTimeoutTable", "header_test.field16") { }

  void SetUp() override {
    ExactOneTest::SetUp();

    mgr.stream_message_response_register_cb([this](
        device_id_t, p4::v1::StreamMessageResponse *msg, void *) {
      if (!msg->has_idle_timeout_notification()) return;
      Lock lock(mutex);
      notifications.push(msg->idle_timeout_notification());
      cvar.notify_one();
    }, nullptr);
  }

  // prevent name hiding
  using ExactOneTest::make_entry;

  template<typename Rep, typename Period>
  p4v1::TableEntry make_entry(
      const boost::optional<std::string> &mf_v,
      const std::string &param_v,
      const std::chrono::duration<Rep, Period> &timeout) {
    auto table_entry = make_entry(mf_v, param_v);
    table_entry.set_idle_timeout_ns(
        std::chrono::duration_cast<std::chrono::nanoseconds>(timeout).count());
    return table_entry;
  }

  template<typename Rep, typename Period>
  boost::optional<p4v1::IdleTimeoutNotification> notification_receive(
      const std::chrono::duration<Rep, Period> &timeout) {
    using Clock = std::chrono::steady_clock;
    Lock lock(mutex);
    // using wait_until and not wait_for to account for spurious awakenings.
    if (cvar.wait_until(lock, Clock::now() + timeout,
                        [this] { return !notifications.empty(); })) {
      auto notification = notifications.front();
      notifications.pop();
      return notification;
    }
    return boost::none;
  }

  boost::optional<p4v1::IdleTimeoutNotification> notification_receive() {
    return notification_receive(defaultTimeout);
  }

  using Lock = std::unique_lock<std::mutex>;

  static constexpr std::chrono::seconds defaultIdleTimeout{1};
  static constexpr std::chrono::milliseconds defaultTimeout{500};
  static constexpr std::chrono::milliseconds negativeTimeout{100};
  // DeviceMgr will not delay notifications (for batching) by more than 100ms
  static constexpr std::chrono::milliseconds notificationMaxDelay{100};

  std::queue<p4v1::IdleTimeoutNotification> notifications;
  mutable std::mutex mutex;
  mutable std::condition_variable cvar;
};

/* static */ constexpr std::chrono::seconds IdleTimeoutTest::defaultIdleTimeout;
/* static */
constexpr std::chrono::milliseconds IdleTimeoutTest::defaultTimeout;
/* static */
constexpr std::chrono::milliseconds IdleTimeoutTest::negativeTimeout;
/* static */
constexpr std::chrono::milliseconds IdleTimeoutTest::notificationMaxDelay;

TEST_F(IdleTimeoutTest, EntryAgeing) {
  std::string mf(2, '\x00');
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata, defaultIdleTimeout);

  auto *entry_matcher_ = new TableEntryMatcher_Direct(a_id, adata);
  entry_matcher_->set_ttl(entry.idle_timeout_ns());
  auto entry_matcher = ::testing::MakeMatcher(entry_matcher_);

  EXPECT_CALL(*mock, table_entry_add(t_id, _, entry_matcher, _));
  EXPECT_OK(add_entry(&entry));
  auto entry_handle = mock->get_table_entry_handle();
  EXPECT_EQ(mock->age_entry(t_id, entry_handle), PI_STATUS_SUCCESS);
  auto notification = notification_receive();
  ASSERT_NE(notification, boost::none);
  ASSERT_EQ(notification->table_entry_size(), 1);
  const auto &table_entry = notification->table_entry(0);
  entry.clear_action();
  EXPECT_TRUE(MessageDifferencer::Equals(table_entry, entry));
  EXPECT_EQ(notification_receive(negativeTimeout), boost::none);
}

// Checks that idle notifications which are close to each other in time are
// batched together in the P4Runtime notification messages (to reduce client
// load). By default the DeviceMgr implementation delays notifications by at
// most 100ms.
TEST_F(IdleTimeoutTest, Buffering) {
  std::string adata(6, '\x00');
  constexpr size_t num_entries = 3;
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(num_entries);
  for (size_t i = 0; i < num_entries; i++) {
    std::string mf(2, static_cast<char>(i));
    auto entry = make_entry(mf, adata, defaultIdleTimeout);
    EXPECT_OK(add_entry(&entry));
    auto entry_handle = mock->get_table_entry_handle();
    EXPECT_EQ(mock->age_entry(t_id, entry_handle), PI_STATUS_SUCCESS);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  auto notification = notification_receive();
  ASSERT_NE(notification, boost::none);
  EXPECT_EQ(notification->table_entry_size(), static_cast<int>(num_entries));
  EXPECT_EQ(notification_receive(negativeTimeout), boost::none);
}

// Checks that notifications are not buffered for too long.
TEST_F(IdleTimeoutTest, MaxBuffering) {
  std::string adata(6, '\x00');
  constexpr size_t num_entries = 3;
  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _)).Times(num_entries);
  for (size_t i = 0; i < num_entries; i++) {
    std::string mf(2, static_cast<char>(i));
    auto entry = make_entry(mf, adata, defaultIdleTimeout);
    EXPECT_OK(add_entry(&entry));
    auto entry_handle = mock->get_table_entry_handle();
    EXPECT_EQ(mock->age_entry(t_id, entry_handle), PI_STATUS_SUCCESS);
    std::this_thread::sleep_for(notificationMaxDelay);
  }
  int num_notifications = 0;
  while (notification_receive() != boost::none) num_notifications++;
  EXPECT_GT(num_notifications, 1);
}

TEST_F(IdleTimeoutTest, ModifyTTL) {
  std::string mf(2, '\x00');
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata, defaultIdleTimeout);

  auto *entry_matcher_ = new TableEntryMatcher_Direct(a_id, adata);
  entry_matcher_->set_ttl(entry.idle_timeout_ns());
  auto entry_matcher = ::testing::MakeMatcher(entry_matcher_);

  EXPECT_CALL(*mock, table_entry_add(t_id, _, entry_matcher, _));
  EXPECT_OK(add_entry(&entry));

  entry.set_idle_timeout_ns(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          2 * defaultIdleTimeout).count());
  entry_matcher_->set_ttl(entry.idle_timeout_ns());

  EXPECT_CALL(*mock, table_entry_modify_wkey(t_id, _, entry_matcher));
  EXPECT_OK(modify_entry(&entry));

  entry_matcher_->set_ttl(boost::none);

  EXPECT_CALL(*mock, table_entry_modify_wkey(t_id, _, entry_matcher));
  EXPECT_OK(modify_entry(&entry));
}

TEST_F(IdleTimeoutTest, ReadEntry) {
  std::string mf(2, '\x00');
  std::string adata(6, '\x00');
  auto entry = make_entry(mf, adata, defaultIdleTimeout);

  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
  EXPECT_OK(add_entry(&entry));

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _)).Times(2);

  {
    p4v1::ReadResponse response;
    auto status = read_table_entry(&entry, &response);
    ASSERT_EQ(status.code(), Code::OK);
    const auto &entities = response.entities();
    ASSERT_EQ(1, entities.size());
    EXPECT_TRUE(
        MessageDifferencer::Equals(entry, entities.Get(0).table_entry()));
  }

  entry.mutable_time_since_last_hit();

  {
    EXPECT_CALL(*mock, table_entry_get_remaining_ttl(t_id, _, _));
    p4v1::ReadResponse response;
    auto status = read_table_entry(&entry, &response);
    ASSERT_EQ(status.code(), Code::OK);
    const auto &entities = response.entities();
    ASSERT_EQ(1, entities.size());
    EXPECT_TRUE(entities.Get(0).table_entry().has_time_since_last_hit());
  }
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
