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

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include "PI/int/pi_int.h"

#include "test_proto_fe_base.h"

namespace pi {
namespace proto {
namespace testing {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::InvokeWithoutArgs;
using ::testing::Return;

namespace {

std::string uint_to_bytes(unsigned int p) {
  std::string res(4, '\x00');
  for (int i = 0; i < 4; i++)
    res[3 - i] = static_cast<char>(p >> (i * 8));
  return res;
}

// fake entries_fetch because gmock does not let us use DoDefault in a composite
// action
pi_status_t fake_entries_fetch(pi_p4_id_t, pi_table_fetch_res_t *res) {
  res->num_entries = 0;
  res->entries = new char[32];
  return PI_STATUS_SUCCESS;
}

}  // namespace

class AccessArbitrationTest : public DeviceMgrUnittestBaseTest {
 protected:
  AccessArbitrationTest() {
    t1_id = pi_p4info_table_id_from_name(p4info, "ExactOne");
    t2_id = pi_p4info_table_id_from_name(p4info, "LpmOne");
    a_id = pi_p4info_action_id_from_name(p4info, "actionA");
    param_id = pi_p4info_action_param_id_from_name(p4info, a_id, "param");
  }

  template <typename MfGen>
  p4v1::WriteRequest make_wreq(pi_p4_id_t t_id, MfGen g,
                               unsigned int start = 0,
                               unsigned int count = 1) const {
    p4v1::WriteRequest req;
    for (unsigned int i = start; i < count; i++) {
      auto update = req.add_updates();
      update->set_type(p4v1::Update::INSERT);
      auto entry = update->mutable_entity()->mutable_table_entry();
      entry->set_table_id(t_id);
      entry->add_match()->CopyFrom(g(i));
      auto action = entry->mutable_action()->mutable_action();
      action->set_action_id(a_id);
      auto param = action->add_params();
      param->set_param_id(param_id);
      param->set_value(std::string(6, '\x00'));
    }
    return req;
  }

  p4v1::WriteRequest make_wreq_t1(unsigned int start = 0,
                                  unsigned int count = 1) const {
    auto mf_id = pi_p4info_table_match_field_id_from_name(
        p4info, t1_id, "header_test.field32");
    return make_wreq(t1_id, [mf_id](unsigned int i) {
        p4v1::FieldMatch mf;
        mf.set_field_id(mf_id);
        mf.mutable_exact()->set_value(uint_to_bytes(i));
        return mf;
    }, start, count);
  }

  p4v1::WriteRequest make_wreq_t2(unsigned int start = 0,
                                  unsigned int count = 1) const {
    auto mf_id = pi_p4info_table_match_field_id_from_name(
        p4info, t2_id, "header_test.field32");
    return make_wreq(t2_id, [mf_id](unsigned int i) {
        p4v1::FieldMatch mf;
        mf.set_field_id(mf_id);
        mf.mutable_lpm()->set_value(uint_to_bytes(i));
        mf.mutable_lpm()->set_prefix_len(32);
        return mf;
    }, start, count);
  }

  p4v1::ReadRequest make_rreq(pi_p4_id_t t_id) const {
    p4v1::ReadRequest req;
    auto entity = req.add_entities();
    auto entry = entity->mutable_table_entry();
    entry->set_table_id(t_id);
    return req;
  }

  p4v1::ReadRequest make_rreq_t1() const {
    return make_rreq(t1_id);
  }

  p4v1::ReadRequest make_rreq_t2() const {
    return make_rreq(t2_id);
  }

  pi_p4_id_t t1_id;
  pi_p4_id_t t2_id;
  pi_p4_id_t a_id;
  pi_p4_id_t param_id;

  mutable std::condition_variable cv;
  mutable std::mutex mutex;

  static constexpr std::chrono::milliseconds timeout{200};
};

/* static */ constexpr std::chrono::milliseconds AccessArbitrationTest::timeout;

// TODO(antonin): unify test code when possible

TEST_F(AccessArbitrationTest, ConcurrentWrites) {
  int x = 0;
  auto action = [this, &x]() -> pi_status_t {
    std::unique_lock<std::mutex> lock(mutex);
    // first thread sets x to 1 and wait for value to change back to 0
    if (x == 0) {
      x = 1;
      cv.notify_one();
      EXPECT_TRUE(cv.wait_for(lock, timeout, [&x] { return x == 0; }));
    } else {
      x = 0;
      cv.notify_one();
    }
    return PI_STATUS_SUCCESS;
  };
  EXPECT_CALL(*mock, table_entry_add(_, _, _, _))
      .WillOnce(InvokeWithoutArgs(action))
      .WillOnce(InvokeWithoutArgs(action));
  // different tables
  auto req1 = make_wreq_t1();
  auto req2 = make_wreq_t2();
  std::thread thread1([&req1, this] { mgr.write(req1); });
  std::thread thread2([&req2, this] { mgr.write(req2); });
  thread1.join();
  thread2.join();
}

TEST_F(AccessArbitrationTest, ExclusiveWrites) {
  int x = 0;
  auto action = [this, &x]() -> pi_status_t {
    std::unique_lock<std::mutex> lock(mutex);
    if (x == 0) {
      x = 1;
      cv.notify_one();
      EXPECT_FALSE(cv.wait_for(lock, timeout, [&x] { return x == 0; }));
    } else {
      x = 0;
      cv.notify_one();
    }
    return PI_STATUS_SUCCESS;
  };
  EXPECT_CALL(*mock, table_entry_add(_, _, _, _))
      .WillOnce(InvokeWithoutArgs(action))
      .WillOnce(InvokeWithoutArgs(action));
  // same table
  auto req1 = make_wreq_t1(0, 1);
  auto req2 = make_wreq_t1(1, 2);
  std::thread thread1([&req1, this] { mgr.write(req1); });
  std::thread thread2([&req2, this] { mgr.write(req2); });
  thread1.join();
  thread2.join();
}

TEST_F(AccessArbitrationTest, ConcurrentReadsSameObject) {
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
  EXPECT_CALL(*mock, table_entries_fetch(_, _))
      .WillOnce(DoAll(InvokeWithoutArgs(action), Invoke(fake_entries_fetch)))
      .WillOnce(DoAll(InvokeWithoutArgs(action), Invoke(fake_entries_fetch)));
  auto req = make_rreq_t1();
  std::thread thread1([&req, this] {
      p4v1::ReadResponse rep;
      mgr.read(req, &rep);
  });
  std::thread thread2([&req, this] {
      p4v1::ReadResponse rep;
      mgr.read(req, &rep);
  });
  thread1.join();
  thread2.join();
}

TEST_F(AccessArbitrationTest, ConcurrentReadsDifferentObjects) {
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
  EXPECT_CALL(*mock, table_entries_fetch(_, _))
      .WillOnce(DoAll(InvokeWithoutArgs(action), Invoke(fake_entries_fetch)))
      .WillOnce(DoAll(InvokeWithoutArgs(action), Invoke(fake_entries_fetch)));
  auto req1 = make_rreq_t1();
  auto req2 = make_rreq_t2();
  std::thread thread1([&req1, this] {
      p4v1::ReadResponse rep;
      mgr.read(req1, &rep);
  });
  std::thread thread2([&req2, this] {
      p4v1::ReadResponse rep;
      mgr.read(req2, &rep);
  });
  thread1.join();
  thread2.join();
}

TEST_F(AccessArbitrationTest, ExclusiveReadAndWrite) {
  int x = 0;
  auto action = [this, &x] {
    std::unique_lock<std::mutex> lock(mutex);
    if (x == 0) {
      x = 1;
      cv.notify_one();
      EXPECT_FALSE(cv.wait_for(lock, timeout, [&x] { return x == 0; }));
    } else {
      x = 0;
      cv.notify_one();
    }
  };
  EXPECT_CALL(*mock, table_entries_fetch(_, _))
      .WillOnce(DoAll(InvokeWithoutArgs(action), Invoke(fake_entries_fetch)));
  EXPECT_CALL(*mock, table_entry_add(_, _, _, _))
      .WillOnce(DoAll(InvokeWithoutArgs(action), Return(PI_STATUS_SUCCESS)));
  auto wreq = make_wreq_t1();
  auto rreq = make_rreq_t1();
  std::thread thread1([&wreq, this] { mgr.write(wreq); });
  std::thread thread2([&rreq, this] {
      p4v1::ReadResponse rep;
      mgr.read(rreq, &rep);
  });
  thread1.join();
  thread2.join();
}

}  // namespace testing
}  // namespace proto
}  // namespace pi
