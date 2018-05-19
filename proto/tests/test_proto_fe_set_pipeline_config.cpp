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

#include <gmock/gmock.h>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include <fstream>  // std::ifstream
#include <string>

#include "PI/frontends/cpp/tables.h"
#include "PI/frontends/proto/device_mgr.h"
#include "PI/int/pi_int.h"
#include "PI/pi.h"

#include "p4info_to_and_from_proto.h"

#include "google/rpc/code.pb.h"

#include "matchers.h"
#include "mock_switch.h"

namespace p4rt = ::p4::v1;
namespace p4config = ::p4::config::v1;

namespace pi {
namespace proto {
namespace testing {
namespace {

using pi::fe::proto::DeviceMgr;
using Code = ::google::rpc::Code;

using ::testing::_;
using ::testing::AnyNumber;

class DeviceMgrSetPipelineConfigTest : public ::testing::Test {
 public:
  DeviceMgrSetPipelineConfigTest()
      : mock(wrapper.sw()), device_id(wrapper.device_id()), mgr(device_id) { }

  static void SetUpTestCase() {
    DeviceMgr::init(256);
  }

  static void TearDownTestCase() {
    DeviceMgr::destroy();
  }

  p4config::P4Info read_p4info(const std::string &p4info_path) {
    p4config::P4Info p4info_proto;
    std::ifstream istream(p4info_path);
    google::protobuf::io::IstreamInputStream istream_(&istream);
    google::protobuf::TextFormat::Parse(&istream_, &p4info_proto);
    return p4info_proto;
  }

  DeviceMgr::Status set_pipeline_config(
      p4config::P4Info *p4info_proto,
      p4rt::SetForwardingPipelineConfigRequest_Action action) {
    p4rt::ForwardingPipelineConfig config;
    config.set_allocated_p4info(p4info_proto);
    auto status = mgr.pipeline_config_set(action, config);
    config.release_p4info();
    return status;
  }

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

  DummySwitchWrapper wrapper{};
  DummySwitchMock *mock;
  device_id_t device_id;
  DeviceMgr mgr;
};

TEST_F(DeviceMgrSetPipelineConfigTest, Reconcile) {
  constexpr const char *p4info_path_1 =
      TESTDATADIR "/" "reconcile_1.p4info.txt";
  constexpr const char *p4info_path_2 =
      TESTDATADIR "/" "reconcile_2.p4info.txt";
  constexpr const char *p4info_path_3 =
      TESTDATADIR "/" "reconcile_3.p4info.txt";
  auto p4info_proto_1 = read_p4info(p4info_path_1);
  auto p4info_proto_2 = read_p4info(p4info_path_2);
  auto p4info_proto_3 = read_p4info(p4info_path_3);

  pi_p4info_t *p4info_1;
  pi::p4info::p4info_proto_reader(p4info_proto_1, &p4info_1);
  auto t_id = pi_p4info_table_id_from_name(p4info_1, "T1");
  auto a_id = pi_p4info_action_id_from_name(p4info_1, "actionA");

  EXPECT_CALL(*mock, table_entries_fetch(t_id, _)).Times(AnyNumber());

  {
    auto status = set_pipeline_config(
        &p4info_proto_1,
        p4rt::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT);
    ASSERT_EQ(status.code(), Code::OK);
  }

  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
  {
    p4rt::TableEntry t_entry;
    t_entry.set_table_id(t_id);
    auto *mf = t_entry.add_match();
    mf->set_field_id(1);
    auto *mf_exact = mf->mutable_exact();
    mf_exact->set_value("\xab");
    auto *entry = t_entry.mutable_action();
    auto *action = entry->mutable_action();
    action->set_action_id(a_id);
    auto param = action->add_params();
    param->set_param_id(1);
    param->set_value("\xab");
    auto status = add_entry(&t_entry);
    ASSERT_EQ(status.code(), Code::OK);
  }

  // config_1 => config_2 is valid
  {
    EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
    auto status = set_pipeline_config(
        &p4info_proto_2,
        p4rt::SetForwardingPipelineConfigRequest_Action_RECONCILE_AND_COMMIT);
    ASSERT_EQ(status.code(), Code::OK);
  }

  // check that table entry is still present
  {
    p4rt::ReadResponse response;
    p4rt::Entity entity;
    auto t_entry = entity.mutable_table_entry();
    t_entry->set_table_id(t_id);
    auto status = mgr.read_one(entity, &response);
    ASSERT_EQ(status.code(), Code::OK);
    EXPECT_EQ(response.entities_size(), 1);
  }

  // config_2 => config_3 is invalid
  {
    auto status = set_pipeline_config(
        &p4info_proto_3,
        p4rt::SetForwardingPipelineConfigRequest_Action_RECONCILE_AND_COMMIT);
    ASSERT_NE(status.code(), Code::OK);
  }
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
