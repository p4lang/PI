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

#include <gmock/gmock.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <tuple>
#include <vector>

#include "PI/frontends/cpp/tables.h"
#include "PI/frontends/proto/device_mgr.h"
#include "PI/int/pi_int.h"

#include "src/access_arbitration.h"
#include "src/common.h"
#include "src/watch_port_enforcer.h"

#include "test_proto_fe_base.h"

namespace pi {
namespace proto {
namespace testing {

using pi::fe::proto::AccessArbitration;
using pi::fe::proto::WatchPortEnforcer;

using ::testing::_;
using ::testing::DoAll;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;

class WatchPortEnforcerTest : public ProtoFrontendBaseTest {
 public:
  WatchPortEnforcerTest()
      : watch_port_enforcer(device_tgt, &access_arbitration) {
    act_prof_id = pi_p4info_act_prof_id_from_name(p4info, "ActProfWS");
  }

  static void SetUpTestCase() {
    DeviceMgr::init(256);
    std::ifstream istream(input_path);
    google::protobuf::io::IstreamInputStream istream_(&istream);
    google::protobuf::TextFormat::Parse(&istream_, &p4info_proto);
    pi::p4info::p4info_proto_reader(p4info_proto, &p4info);
  }

  static void TearDownTestCase() {
    DeviceMgr::destroy();
  }

  void SetUp() override {
    for (size_t i = 0; i < numPorts; i++) {
      auto port = static_cast<pi_port_t>(i);
      EXPECT_EQ(mock->port_status_set(port, PI_PORT_STATUS_UP),
                PI_STATUS_SUCCESS);
    }
    ASSERT_OK(watch_port_enforcer.p4_change(p4info));
  }

  void process_all_port_events() {
    // the call to p4_change will block until the async task queue is empty (all
    // events have been processed)
    ASSERT_OK(watch_port_enforcer.p4_change(p4info));
  }

  mutable std::condition_variable cv;
  mutable std::mutex mutex;

  static constexpr size_t numPorts = 16;
  static constexpr const char *input_path =
           TESTDATADIR "/" "unittest.p4info.txt";
  static constexpr std::chrono::milliseconds timeout{200};
  static pi_p4info_t *p4info;
  static p4configv1::P4Info p4info_proto;

  AccessArbitration access_arbitration;
  WatchPortEnforcer watch_port_enforcer;
  pi_p4_id_t act_prof_id;
  pi_indirect_handle_t grp_h{10};
  pi_indirect_handle_t mbr_h{20};
  pi_port_t watch_1{1};
  pi_port_t watch_2{2};
};


/* static */ constexpr std::chrono::milliseconds WatchPortEnforcerTest::timeout;
/* static */ pi_p4info_t *WatchPortEnforcerTest::p4info = nullptr;
/* static */ p4configv1::P4Info WatchPortEnforcerTest::p4info_proto;

TEST_F(WatchPortEnforcerTest, DontUpdateHw) {
  EXPECT_CALL(*mock, action_prof_group_activate_member(act_prof_id, _, _))
      .Times(0);
  EXPECT_CALL(*mock, action_prof_group_deactivate_member(act_prof_id, _, _))
      .Times(0);

  watch_port_enforcer.handle_port_status_event_sync(
      watch_1, PI_PORT_STATUS_DOWN);
  EXPECT_OK(watch_port_enforcer.add_member(
      act_prof_id, grp_h, mbr_h, watch_1));

  // down -> up
  EXPECT_OK(watch_port_enforcer.modify_member(
      act_prof_id, grp_h, mbr_h, watch_1, watch_2));

  // up -> down
  EXPECT_OK(watch_port_enforcer.modify_member(
      act_prof_id, grp_h, mbr_h, watch_2, watch_1));

  EXPECT_OK(watch_port_enforcer.delete_member(
      act_prof_id, grp_h, mbr_h, watch_1));

  watch_port_enforcer.handle_port_status_event_sync(
      watch_1, PI_PORT_STATUS_UP);
  EXPECT_OK(watch_port_enforcer.add_member(
      act_prof_id, grp_h, mbr_h, watch_1));
}

TEST_F(WatchPortEnforcerTest, UpdateHw) {
  ::pi::fe::proto::common::SessionTemp session;
  ::pi::ActProf ap(session.get(), device_tgt, p4info, act_prof_id);

  watch_port_enforcer.handle_port_status_event_sync(
      watch_1, PI_PORT_STATUS_DOWN);
  EXPECT_CALL(
      *mock, action_prof_group_deactivate_member(act_prof_id, grp_h, mbr_h));
  EXPECT_OK(watch_port_enforcer.add_member_and_update_hw(
      &ap, grp_h, mbr_h, watch_1));

  // down -> up
  EXPECT_CALL(
      *mock, action_prof_group_activate_member(act_prof_id, grp_h, mbr_h));
  EXPECT_OK(watch_port_enforcer.modify_member_and_update_hw(
      &ap, grp_h, mbr_h, watch_1, watch_2));

  // up -> down
  EXPECT_CALL(
      *mock, action_prof_group_deactivate_member(act_prof_id, grp_h, mbr_h));
  EXPECT_OK(watch_port_enforcer.modify_member_and_update_hw(
      &ap, grp_h, mbr_h, watch_2, watch_1));

  EXPECT_OK(watch_port_enforcer.delete_member(
      act_prof_id, grp_h, mbr_h, watch_1));

  watch_port_enforcer.handle_port_status_event_sync(
      watch_1, PI_PORT_STATUS_UP);
  EXPECT_OK(watch_port_enforcer.add_member_and_update_hw(
      &ap, grp_h, mbr_h, watch_1));
}

TEST_F(WatchPortEnforcerTest, PortStatusEvents) {
  std::vector<pi_indirect_handle_t> mbrs(numPorts);
  pi_indirect_handle_t mbr_h = 0;
  std::generate(mbrs.begin(), mbrs.end(), [&mbr_h] { return mbr_h++; });

  for (size_t i = 0; i < numPorts; i++) {
    auto port = static_cast<pi_port_t>(i);
    EXPECT_OK(watch_port_enforcer.add_member(
        act_prof_id, grp_h, mbrs[i], port));
  }

  EXPECT_CALL(*mock, action_prof_group_deactivate_member(act_prof_id, grp_h, _))
      .Times(numPorts);

  for (size_t i = 0; i < numPorts; i++) {
    auto port = static_cast<pi_port_t>(i);
    watch_port_enforcer.handle_port_status_event_sync(
        port, PI_PORT_STATUS_DOWN);
  }

  EXPECT_CALL(*mock, action_prof_group_activate_member(act_prof_id, grp_h, _))
      .Times(numPorts);

  for (size_t i = 0; i < numPorts; i++) {
    auto port = static_cast<pi_port_t>(i);
    watch_port_enforcer.handle_port_status_event_sync(
        port, PI_PORT_STATUS_UP);
  }

  for (size_t i = 0; i < numPorts; i++) {
    auto port = static_cast<pi_port_t>(i);
    EXPECT_OK(watch_port_enforcer.delete_member(
        act_prof_id, grp_h, mbrs[i], port));
  }
}

TEST_F(WatchPortEnforcerTest, ConcurrentRead) {
  int x = 0;
  auto action = [this, &x] {
    std::unique_lock<std::mutex> lock(mutex);
    if (x == 0) {
      x = 1;
      EXPECT_TRUE(cv.wait_for(lock, timeout, [&x] { return x == 0; }));
    } else {
      x = 0;
      cv.notify_one();
    }
  };
  EXPECT_CALL(*mock, action_prof_group_deactivate_member(
      act_prof_id, grp_h, mbr_h))
      .WillOnce(DoAll(InvokeWithoutArgs(action), Return(PI_STATUS_SUCCESS)));
  std::thread thread1([this, &action] {
      AccessArbitration::ReadAccess access(&access_arbitration);
      action();
  });
  EXPECT_OK(watch_port_enforcer.add_member(act_prof_id, grp_h, mbr_h, watch_1));
  EXPECT_EQ(mock->port_status_set(watch_1, PI_PORT_STATUS_DOWN),
            PI_STATUS_SUCCESS);
  thread1.join();
  // we need to call this, otherwise the call to action() triggered by the call
  // to action_prof_group_deactivate_member may not have completed yet
  process_all_port_events();
}

TEST_F(WatchPortEnforcerTest, ExclusiveWrite) {
  int x = 0;
  auto action = [this, &x] {
    std::unique_lock<std::mutex> lock(mutex);
    if (x == 0) {
      x = 1;
      EXPECT_FALSE(cv.wait_for(lock, timeout, [&x] { return x == 0; }));
    } else {
      x = 0;
      cv.notify_one();
    }
  };
  EXPECT_CALL(*mock, action_prof_group_deactivate_member(
      act_prof_id, grp_h, mbr_h))
      .WillOnce(DoAll(InvokeWithoutArgs(action), Return(PI_STATUS_SUCCESS)));
  std::thread thread1([this, &action] {
      AccessArbitration::WriteAccess access(&access_arbitration, act_prof_id);
      action();
  });
  EXPECT_OK(watch_port_enforcer.add_member(act_prof_id, grp_h, mbr_h, watch_1));
  EXPECT_EQ(mock->port_status_set(watch_1, PI_PORT_STATUS_DOWN),
            PI_STATUS_SUCCESS);
  thread1.join();
  process_all_port_events();
}

// make sure that there is no deadlock when updating pipeline config
TEST_F(WatchPortEnforcerTest, UpdateConfig) {
  EXPECT_OK(watch_port_enforcer.add_member(act_prof_id, grp_h, mbr_h, watch_1));
  AccessArbitration::UpdateAccess access(&access_arbitration);
  EXPECT_EQ(mock->port_status_set(watch_1, PI_PORT_STATUS_DOWN),
            PI_STATUS_SUCCESS);
  EXPECT_OK(watch_port_enforcer.p4_change(p4info));
}

using ::testing::WithParamInterface;
using ::testing::Values;

class WatchPortEnforcerNoWriteAccessOneOfTest
    : public WatchPortEnforcerTest,
      public WithParamInterface<std::tuple<const char *, const char *> > { };

// We test that when there is an ongoing WriteRequest for one action profile,
// port status events can still be processed concurrently for other action
// profiles.
TEST_P(WatchPortEnforcerNoWriteAccessOneOfTest, ConcurrentAccess) {
  pi_p4_id_t act_prof_1_id = pi_p4info_act_prof_id_from_name(
      p4info, std::get<0>(GetParam()));
  pi_p4_id_t act_prof_2_id = pi_p4info_act_prof_id_from_name(
      p4info, std::get<1>(GetParam()));

  int x = 0;
  auto action = [this, &x] {
    std::unique_lock<std::mutex> lock(mutex);
    if (x == 0) {
      x = 1;
      cv.notify_one();
      EXPECT_TRUE(cv.wait_for(lock, timeout, [&x] { return x == 0; }));
    } else {
      x = 0;
      cv.notify_one();
    }
  };
  EXPECT_CALL(*mock, action_prof_group_deactivate_member(_, grp_h, mbr_h))
      .WillOnce(DoAll(InvokeWithoutArgs(action), Return(PI_STATUS_SUCCESS)))
      .WillOnce(Return(PI_STATUS_SUCCESS));
  std::thread thread1([this, act_prof_1_id, &action] {
      AccessArbitration::WriteAccess access(&access_arbitration, act_prof_1_id);
      action();
  });
  {
    std::unique_lock<std::mutex> lock(mutex);
    cv.wait(lock, [&x] { return x == 1; });
  }
  EXPECT_OK(watch_port_enforcer.add_member(
      act_prof_1_id, grp_h, mbr_h, watch_1));
  EXPECT_OK(watch_port_enforcer.add_member(
      act_prof_2_id, grp_h, mbr_h, watch_1));
  // Make sure that thread1 has grabbed WriteAccess before we bring the port
  // down. Otherwise the WatchPortEnforcer may grab access to act_prof_1 first
  // and block thread1. The wait_for would then timeout in thread1 and the test
  // would fail.
  EXPECT_EQ(mock->port_status_set(watch_1, PI_PORT_STATUS_DOWN),
            PI_STATUS_SUCCESS);
  thread1.join();
  process_all_port_events();
}

INSTANTIATE_TEST_SUITE_P(
    ConcurrentAccess, WatchPortEnforcerNoWriteAccessOneOfTest,
    Values(std::make_tuple("ActProfWS", "ActProfWS2"),
           std::make_tuple("ActProfWS2", "ActProfWS")));

}  // namespace testing
}  // namespace proto
}  // namespace pi
