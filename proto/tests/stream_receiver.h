// Copyright 2019 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PROTO_TESTS_STREAM_RECEIVER_H_
#define PROTO_TESTS_STREAM_RECEIVER_H_

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>

#include <boost/optional.hpp>

#include "p4/v1/p4runtime.pb.h"

namespace p4v1 = ::p4::v1;

namespace pi {
namespace proto {
namespace testing {

namespace details {

template <typename T>
struct OneOfCase;

template <> struct OneOfCase<p4v1::MasterArbitrationUpdate> {
  static constexpr p4v1::StreamMessageResponse::UpdateCase value =
      p4v1::StreamMessageResponse::kArbitration;

  static const p4v1::MasterArbitrationUpdate &
  from(p4::v1::StreamMessageResponse *msg) {
    return msg->arbitration();
  }
};

template <> struct OneOfCase<p4v1::PacketIn> {
  static constexpr p4v1::StreamMessageResponse::UpdateCase value =
      p4v1::StreamMessageResponse::kPacket;

  static const p4v1::PacketIn &
  from(p4::v1::StreamMessageResponse *msg) {
    return msg->packet();
  }
};

template <> struct OneOfCase<p4v1::DigestList> {
  static constexpr p4v1::StreamMessageResponse::UpdateCase value =
      p4v1::StreamMessageResponse::kDigest;

  static const p4v1::DigestList &
  from(p4::v1::StreamMessageResponse *msg) {
    return msg->digest();
  }
};

template <> struct OneOfCase<p4v1::IdleTimeoutNotification> {
  static constexpr p4v1::StreamMessageResponse::UpdateCase value =
      p4v1::StreamMessageResponse::kIdleTimeoutNotification;

  static const p4v1::IdleTimeoutNotification &
  from(p4::v1::StreamMessageResponse *msg) {
    return msg->idle_timeout_notification();
  }
};

template <> struct OneOfCase<p4v1::StreamError> {
  static constexpr p4v1::StreamMessageResponse::UpdateCase value =
      p4v1::StreamMessageResponse::kError;

  static const p4v1::StreamError &
  from(p4::v1::StreamMessageResponse *msg) {
    return msg->error();
  }
};

}  // namespace details

template <typename T>
class StreamReceiver {
 public:
  explicit StreamReceiver(pi::fe::proto::DeviceMgr *mgr) {
    mgr->stream_message_response_register_cb([this](
        device_id_t, p4::v1::StreamMessageResponse *msg, void *) {
      if (msg->update_case() != details::OneOfCase<T>::value) return;
      Lock lock(mutex);
      msgs.push(details::OneOfCase<T>::from(msg));
      cvar.notify_one();
    }, nullptr);
  }

  template <typename Rep, typename Period>
  boost::optional<T> get(const std::chrono::duration<Rep, Period> &timeout) {
        using Clock = std::chrono::steady_clock;
    Lock lock(mutex);
    // using wait_until and not wait_for to account for spurious awakenings.
    if (cvar.wait_until(lock, Clock::now() + timeout,
                        [this] { return !msgs.empty(); })) {
      auto msg = msgs.front();
      msgs.pop();
      return msg;
    }
    return boost::none;
  }

 private:
  using Lock = std::unique_lock<std::mutex>;
  std::queue<T> msgs;
  mutable std::mutex mutex;
  mutable std::condition_variable cvar;
};

}  // namespace testing
}  // namespace proto
}  // namespace pi

#endif  // PROTO_TESTS_STREAM_RECEIVER_H_
