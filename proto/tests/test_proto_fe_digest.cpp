/* Copyright 2018-present Barefoot Networks, Inc.
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

#include <algorithm>  // std::transform
#include <chrono>
#include <condition_variable>
#include <fstream>  // std::ifstream
#include <iterator>  // std::back_inserter
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "src/common.h"
#include "src/digest_mgr.h"

#include "google/rpc/code.pb.h"

#include "matchers.h"
#include "mock_switch.h"

namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;

namespace pi {
namespace proto {
namespace testing {
namespace {

using pi::fe::proto::DigestMgr;
using Status = DigestMgr::Status;
using Code = ::google::rpc::Code;
using Clock = std::chrono::steady_clock;
using SessionTemp = pi::fe::proto::common::SessionTemp;

using ::testing::_;
using ::testing::AnyNumber;

class Sample {
 public:
  Sample &operator<<(std::string s) {
    values.push_back(std::move(s));
    return *this;
  }

  bool eq(const p4v1::P4Data &data) const {
    if (data.data_case() != p4v1::P4Data::kStruct) return false;
    std::vector<std::string> tmp;
    for (const auto &member : data.struct_().members()) {
      if (member.data_case() != p4v1::P4Data::kBitstring) return false;
      tmp.push_back(member.bitstring());
    }
    return (tmp == values);
  }

  std::string get() const {
    std::string ret;
    for (const auto &v : values) ret.append(v);
    return ret;
  }

 private:
  std::vector<std::string> values{};
};

class DigestMgrTest : public ::testing::Test {
 public:
  DigestMgrTest()
      : mock(wrapper.sw()),
        device_id(wrapper.device_id()),
        digest_mgr(device_id) { }

  static void SetUpTestCase() {
    std::ifstream istream(input_path);
    google::protobuf::io::IstreamInputStream istream_(&istream);
    google::protobuf::TextFormat::Parse(&istream_, &p4info_proto);
    for (const auto &digest : p4info_proto.digests()) {
      const auto &pre = digest.preamble();
      if (pre.name() == "test_digest_t") {
        digest_id = pre.id();
        break;
      }
    }
    ASSERT_NE(digest_id, 0u);
  }

  static void TearDownTestCase() { }

  void SetUp() override {
    auto status = digest_mgr.p4_change(p4info_proto);
    ASSERT_OK(status);

    digest_mgr.stream_message_response_register_cb([this](
        device_id_t, p4::v1::StreamMessageResponse *msg, void *) {
      if (!msg->has_digest()) return;
      Lock lock(mutex);
      digests.push(msg->digest());
      cvar.notify_one();
    }, nullptr);
  }

  void TearDown() override {
    digest_mgr.stream_message_response_unregister_cb();
  }

  pi_status_t digest_inject(const std::vector<Sample> &samples) {
    std::vector<std::string> samples_;
    std::transform(samples.begin(), samples.end(), std::back_inserter(samples_),
                   [](const Sample &s) { return s.get(); });
    return mock->digest_inject(digest_id, ++msg_id, samples_);
  }

  template<typename Rep, typename Period>
  boost::optional<p4v1::DigestList> digest_receive(
      const std::chrono::duration<Rep, Period> &timeout) {
    Lock lock(mutex);
    // using wait_until and not wait_for to account for spurious awakenings.
    // if (cvar.wait_for(lock, timeout, [this] { return !digests.empty(); })) {
    if (cvar.wait_until(lock, Clock::now() + timeout,
                        [this] { return !digests.empty(); })) {
      auto digest = digests.front();
      digests.pop();
      return digest;
    }
    return boost::none;
  }

  boost::optional<p4v1::DigestList> digest_receive() {
    return digest_receive(defaultTimeout);
  }

  Status config_write(const p4v1::DigestEntry &entry,
                      p4v1::Update::Type type = p4v1::Update::INSERT) {
    EXPECT_CALL(
        *mock, learn_config_set(digest_id, EqDigestConfig(entry.config())));
    return digest_mgr.config_write(entry, type, session);
  }

  Status config_delete() {
    p4v1::DigestEntry entry;
    entry.set_digest_id(digest_id);
    EXPECT_CALL(*mock, learn_config_set(digest_id, NULL));
    return digest_mgr.config_write(entry, p4v1::Update::DELETE, session);
  }

  template<typename Rep1, typename Period1, typename Rep2, typename Period2>
  Status config_digest(
      int32_t max_list_size,
      const std::chrono::duration<Rep1, Period1> &max_timeout,
      const std::chrono::duration<Rep2, Period2> &ack_timeout,
      p4v1::Update::Type type = p4v1::Update::INSERT) {
    auto max_timeout_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        max_timeout).count();
    auto ack_timeout_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        ack_timeout).count();
    p4v1::DigestEntry entry;
    entry.set_digest_id(digest_id);
    auto *config = entry.mutable_config();
    config->set_max_list_size(max_list_size);
    config->set_max_timeout_ns(max_timeout_ns);
    config->set_ack_timeout_ns(ack_timeout_ns);
    return config_write(entry, type);
  }

  Status config_digest_default(p4v1::Update::Type type = p4v1::Update::INSERT) {
    p4v1::DigestEntry entry;
    entry.set_digest_id(digest_id);
    return config_write(entry, type);
  }

 protected:
  using Lock = std::unique_lock<std::mutex>;

  static constexpr const char *input_path =
           TESTDATADIR "/" "unittest.p4info.txt";
  static p4configv1::P4Info p4info_proto;
  static pi_p4_id_t digest_id;
  static constexpr std::chrono::milliseconds defaultTimeout{100};

  DummySwitchWrapper wrapper{};
  DummySwitchMock *mock;
  device_id_t device_id;
  std::queue<p4v1::DigestList> digests;
  mutable std::mutex mutex;
  mutable std::condition_variable cvar;
  DigestMgr digest_mgr;
  pi_learn_msg_id_t msg_id{0};
  SessionTemp session{false  /* = batch */};
};

/* static */ p4configv1::P4Info DigestMgrTest::p4info_proto;
/* static */ pi_p4_id_t DigestMgrTest::digest_id = 0;
/* static */ constexpr std::chrono::milliseconds DigestMgrTest::defaultTimeout;

TEST_F(DigestMgrTest, Default) {
  ASSERT_OK(config_digest_default());
  Sample s;
  s << "\x11\x22\x33\x44\x55\x66" << "\x01\x23";
  EXPECT_CALL(*mock, learn_msg_ack(digest_id, _));
  EXPECT_CALL(*mock, learn_msg_done(_));
  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  auto digest = digest_receive();
  ASSERT_NE(digest, boost::none);
  EXPECT_EQ(digest->digest_id(), digest_id);
  EXPECT_EQ(digest->data_size(), 1);
  EXPECT_TRUE(s.eq(digest->data(0)));
}

TEST_F(DigestMgrTest, Cache) {
  ASSERT_OK(config_digest_default());
  auto ack_timeout = std::chrono::milliseconds(100);
  auto ack_timeout_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
      ack_timeout).count();
  Sample s;
  s << "\x11\x22\x33\x44\x55\x66" << "\x01\x23";
  EXPECT_CALL(*mock, learn_msg_ack(digest_id, _)).Times(AnyNumber());
  EXPECT_CALL(*mock, learn_msg_done(_)).Times(AnyNumber());

  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  ASSERT_NE(digest_receive(), boost::none);
  ASSERT_NE(digest_receive(), boost::none);  // default config: no cache

  p4v1::DigestEntry config;
  config.set_digest_id(digest_id);
  config.mutable_config()->set_ack_timeout_ns(ack_timeout_ns);
  ASSERT_OK(config_write(config, p4v1::Update::MODIFY));

  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  ASSERT_NE(digest_receive(), boost::none);
  ASSERT_EQ(digest_receive(3 * ack_timeout), boost::none);  // cache hit
  // we have waited 3 * ack_timeout, cache should be clear
  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  ASSERT_NE(digest_receive(), boost::none);
}

TEST_F(DigestMgrTest, Ack) {
  auto ack_timeout = std::chrono::milliseconds(1000);
  auto ack_timeout_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
      ack_timeout).count();
  p4v1::DigestEntry config;
  config.set_digest_id(digest_id);
  config.mutable_config()->set_ack_timeout_ns(ack_timeout_ns);
  ASSERT_OK(config_write(config, p4v1::Update::INSERT));

  Sample s;
  s << "\x11\x22\x33\x44\x55\x66" << "\x01\x23";
  EXPECT_CALL(*mock, learn_msg_ack(digest_id, _)).Times(AnyNumber());
  EXPECT_CALL(*mock, learn_msg_done(_)).Times(AnyNumber());

  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  auto digest = digest_receive();
  ASSERT_NE(digest, boost::none);
  // cache hit
  ASSERT_EQ(digest_receive(std::chrono::milliseconds(200)), boost::none);
  p4v1::DigestListAck ack;
  ack.set_digest_id(digest_id);
  ack.set_list_id(digest->list_id());
  digest_mgr.ack(ack);
  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  // the ack call is asynchronous and there is no way to get completion
  // information, but we assume that 200ms is long enough for it to complete
  ASSERT_NE(digest_receive(std::chrono::milliseconds(200)), boost::none);
}

TEST_F(DigestMgrTest, MaxListSize) {
  ASSERT_OK(config_digest(
      2, std::chrono::milliseconds(1000), std::chrono::milliseconds(1000)));

  EXPECT_CALL(*mock, learn_msg_ack(digest_id, _)).Times(AnyNumber());
  EXPECT_CALL(*mock, learn_msg_done(_)).Times(AnyNumber());

  {
    Sample s;
    s << "\x11\x22\x33\x44\x55\x66" << "\x01\x23";
    ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  }
  {
    Sample s;
    s << "\x11\x22\x33\x44\x55\x66" << "\x23\x45";
    ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  }
  auto digest = digest_receive(std::chrono::milliseconds(500));
  ASSERT_NE(digest, boost::none);
  EXPECT_EQ(digest->data_size(), 2);
}

TEST_F(DigestMgrTest, MaxTimeout) {
  auto max_timeout = std::chrono::milliseconds(400);
  auto ack_timeout = std::chrono::milliseconds(2000);
  ASSERT_OK(config_digest(100, max_timeout, ack_timeout));

  EXPECT_CALL(*mock, learn_msg_ack(digest_id, _)).Times(AnyNumber());
  EXPECT_CALL(*mock, learn_msg_done(_)).Times(AnyNumber());

  Sample s;
  s << "\x11\x22\x33\x44\x55\x66" << "\x01\x23";
  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  auto sent_at = Clock::now();
  ASSERT_NE(digest_receive(std::chrono::milliseconds(1000)), boost::none);
  auto received_at = Clock::now();
  auto diff = received_at - sent_at;
  EXPECT_GT(diff, max_timeout / 2);
  // it can take up to twice the max_timeout based on the current implementation
  EXPECT_LT(diff, max_timeout * 3);
}

TEST_F(DigestMgrTest, Reset) {
  auto ack_timeout = std::chrono::seconds(10);
  auto ack_timeout_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
      ack_timeout).count();
  Sample s;
  s << "\x11\x22\x33\x44\x55\x66" << "\x01\x23";

  EXPECT_CALL(*mock, learn_msg_ack(digest_id, _)).Times(AnyNumber());
  EXPECT_CALL(*mock, learn_msg_done(_)).Times(AnyNumber());

  p4v1::DigestEntry config;
  config.set_digest_id(digest_id);
  config.mutable_config()->set_ack_timeout_ns(ack_timeout_ns);
  ASSERT_OK(config_write(config, p4v1::Update::INSERT));

  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  ASSERT_NE(digest_receive(), boost::none);

  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  ASSERT_EQ(digest_receive(), boost::none);  // cache hit

  // deleting the config should reset the state of the DigestMgr, so it should
  // clear the cache
  ASSERT_OK(config_delete());
  ASSERT_OK(config_write(config, p4v1::Update::INSERT));
  ASSERT_EQ(digest_inject({s}), PI_STATUS_SUCCESS);
  ASSERT_NE(digest_receive(), boost::none);
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
