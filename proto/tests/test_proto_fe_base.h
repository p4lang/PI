/* Copyright 2019-present Barefoot Networks, Inc.
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

#ifndef PROTO_TESTS_TEST_PROTO_FE_BASE_H_
#define PROTO_TESTS_TEST_PROTO_FE_BASE_H_

#include <gmock/gmock.h>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include <fstream>  // std::ifstream
#include <string>

#include "PI/frontends/proto/device_mgr.h"
#include "PI/p4info.h"

#include "PI/proto/p4info_to_and_from_proto.h"

#include "google/rpc/code.pb.h"

#include "matchers.h"
#include "mock_switch.h"

namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;

namespace pi {
namespace proto {
namespace testing {

using pi::fe::proto::DeviceMgr;
using Code = ::google::rpc::Code;

class ProtoFrontendBaseTest : public ::testing::Test {
 public:
  ProtoFrontendBaseTest()
      : mock(wrapper.sw()), device_id(wrapper.device_id()),
        device_tgt({static_cast<pi_dev_id_t>(device_id), 0xffff}) { }

  static void SetUpTestCase() {
    DeviceMgr::init(256);
  }

  static void TearDownTestCase() {
    DeviceMgr::destroy();
  }

  DummySwitchWrapper wrapper{};
  DummySwitchMock *mock;
  device_id_t device_id;
  pi_dev_tgt_t device_tgt;
};

class DeviceMgrBaseTest : public ProtoFrontendBaseTest {
 public:
  DeviceMgrBaseTest()
      : mgr(device_id) { }

  DeviceMgr::Status set_pipeline_config(
      p4configv1::P4Info *p4info_proto,
      uint64_t cookie = 0,
      const std::string &device_config = defaultDeviceConfig) {
    using ::testing::_;
    EXPECT_CALL(*mock, action_prof_api_support())
        .WillRepeatedly(::testing::Return(action_prof_api_choice));
    EXPECT_CALL(*mock, table_default_action_get_handle(_, _))
        .Times(::testing::AnyNumber());

    p4v1::ForwardingPipelineConfig config;
    config.set_allocated_p4info(p4info_proto);
    config.mutable_cookie()->set_cookie(cookie);
    config.set_p4_device_config(device_config);
    auto status = mgr.pipeline_config_set(
        p4v1::SetForwardingPipelineConfigRequest::VERIFY_AND_COMMIT, config);
    config.release_p4info();
    return status;
  }

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

  static constexpr const char *defaultDeviceConfig =
      "This is a dummy device config";
  static constexpr const char *invalid_p4_id_error_str = "Invalid P4 id";

  DeviceMgr mgr;
  PiActProfApiSupport action_prof_api_choice{PiActProfApiSupport_BOTH};
};

class DeviceMgrUnittestBaseTest : public DeviceMgrBaseTest {
 public:
  static void SetUpTestCase() {
    DeviceMgrBaseTest::SetUpTestCase();
    std::ifstream istream(input_path);
    google::protobuf::io::IstreamInputStream istream_(&istream);
    google::protobuf::TextFormat::Parse(&istream_, &p4info_proto);
    pi::p4info::p4info_proto_reader(p4info_proto, &p4info);
  }

  static void TearDownTestCase() {
    pi_destroy_config(p4info);
    DeviceMgrBaseTest::TearDownTestCase();
  }

  void SetUp() override {
    dummy_device_config = defaultDeviceConfig;
    EXPECT_CALL(*mock, table_idle_timeout_config_set(
        pi_p4info_table_id_from_name(p4info, "IdleTimeoutTable"),
        ::testing::_));
    auto status = set_pipeline_config(
        &p4info_proto, cookie, dummy_device_config);
    ASSERT_OK(status);
  }

  void TearDown() override { }

  static constexpr const char *input_path =
           TESTDATADIR "/" "unittest.p4info.txt";
  static pi_p4info_t *p4info;
  static p4configv1::P4Info p4info_proto;

  uint64_t cookie{666};
  std::string dummy_device_config;
};

}  // namespace testing
}  // namespace proto
}  // namespace pi

#endif  // PROTO_TESTS_TEST_PROTO_FE_BASE_H_
