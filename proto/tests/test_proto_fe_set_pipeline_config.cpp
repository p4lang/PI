/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
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
#include <google/protobuf/util/message_differencer.h>

#include <fstream>  // std::ifstream
#include <string>

#include "PI/frontends/cpp/tables.h"
#include "PI/frontends/proto/device_mgr.h"
#include "PI/int/pi_int.h"
#include "PI/pi.h"

#include "PI/proto/p4info_to_and_from_proto.h"

#include "google/rpc/code.pb.h"

#include "matchers.h"
#include "mock_switch.h"
#include "test_proto_fe_base.h"

namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;

namespace pi {
namespace proto {
namespace testing {
namespace {

using google::protobuf::util::MessageDifferencer;
using pi::fe::proto::DeviceMgr;
using Code = ::google::rpc::Code;

using ::testing::_;
using ::testing::AnyNumber;

class DeviceMgrSetPipelineConfigTest : public DeviceMgrBaseTest {
 public:
  p4configv1::P4Info read_p4info(const std::string &p4info_path) {
    p4configv1::P4Info p4info_proto;
    std::ifstream istream(p4info_path);
    google::protobuf::io::IstreamInputStream istream_(&istream);
    google::protobuf::TextFormat::Parse(&istream_, &p4info_proto);
    return p4info_proto;
  }

  DeviceMgr::Status set_pipeline_config(
      p4configv1::P4Info *p4info_proto,
      p4v1::SetForwardingPipelineConfigRequest_Action action) {
    EXPECT_CALL(*mock, action_prof_api_support())
        .Times(AnyNumber());
    EXPECT_CALL(*mock, table_default_action_get_handle(_, _))
        .Times(AnyNumber());

    p4v1::ForwardingPipelineConfig config;
    config.unsafe_arena_set_allocated_p4info(p4info_proto);
    auto status = mgr.pipeline_config_set(action, config);
    config.unsafe_arena_release_p4info();
    return status;
  }
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
        p4v1::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT);
    ASSERT_OK(status);
  }

  EXPECT_CALL(*mock, table_entry_add(t_id, _, _, _));
  {
    p4v1::TableEntry t_entry;
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
        p4v1::SetForwardingPipelineConfigRequest_Action_RECONCILE_AND_COMMIT);
    ASSERT_EQ(status.code(), Code::OK);
  }

  // check that table entry is still present
  {
    p4v1::ReadResponse response;
    p4v1::Entity entity;
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
        p4v1::SetForwardingPipelineConfigRequest_Action_RECONCILE_AND_COMMIT);
    ASSERT_NE(status.code(), Code::OK);
  }
}

// Counters and meters are part of the forwarding state which is preserved by
// RECONCILE_AND_COMMIT; since their cells always exist, they must be replayed
// with MODIFY updates.
TEST_F(DeviceMgrSetPipelineConfigTest, ReconcileCountersMeters) {
  constexpr const char *p4info_path = TESTDATADIR "/" "unittest.p4info.txt";
  auto p4info_proto = read_p4info(p4info_path);
  pi_p4info_t *p4info;
  pi::p4info::p4info_proto_reader(p4info_proto, &p4info);
  auto c_id = pi_p4info_counter_id_from_name(p4info, "CounterA");
  auto m_id = pi_p4info_meter_id_from_name(p4info, "MeterA");
  pi_destroy_config(p4info);

  EXPECT_CALL(*mock, table_idle_timeout_config_set(_, _)).Times(AnyNumber());
  ASSERT_OK(set_pipeline_config(
      &p4info_proto,
      p4v1::SetForwardingPipelineConfigRequest_Action_VERIFY_AND_COMMIT));

  p4v1::Entity counter_entity;
  auto *counter_entry = counter_entity.mutable_counter_entry();
  counter_entry->set_counter_id(c_id);
  counter_entry->mutable_index()->set_index(3);
  counter_entry->mutable_data()->set_packet_count(10);
  p4v1::Entity meter_entity;
  auto *meter_entry = meter_entity.mutable_meter_entry();
  meter_entry->set_meter_id(m_id);
  meter_entry->mutable_index()->set_index(4);
  auto *meter_config = meter_entry->mutable_config();
  meter_config->set_cir(10);
  meter_config->set_cburst(5);
  meter_config->set_pir(100);
  meter_config->set_pburst(50);
  {
    p4v1::WriteRequest request;
    for (const auto *entity : {&counter_entity, &meter_entity}) {
      auto *update = request.add_updates();
      update->set_type(p4v1::Update::MODIFY);
      update->mutable_entity()->CopyFrom(*entity);
    }
    ASSERT_OK(mgr.write(request));
  }

  ASSERT_OK(set_pipeline_config(
      &p4info_proto,
      p4v1::SetForwardingPipelineConfigRequest_Action_RECONCILE_AND_COMMIT));

  for (const auto *entity : {&counter_entity, &meter_entity}) {
    p4v1::ReadResponse response;
    ASSERT_OK(mgr.read_one(*entity, &response));
    ASSERT_EQ(1, response.entities_size());
    EXPECT_TRUE(MessageDifferencer::Equals(*entity, response.entities(0)))
        << response.entities(0).DebugString();
  }
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
