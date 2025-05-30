/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
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
 * Antonin Bas
 *
 */

#include <gmock/gmock.h>

#include <algorithm>  // for std::reverse
#include <string>
#include <tuple>
#include <vector>

#include "PI/frontends/proto/device_mgr.h"

#include "google/rpc/code.pb.h"

#include "server_config/server_config.h"
#include "src/packet_io_mgr.h"

#include "matchers.h"
#include "mock_switch.h"
#include "test_proto_fe_base.h"

namespace p4v1 = ::p4::v1;
namespace p4configv1 = ::p4::config::v1;

namespace pi {
namespace proto {
namespace testing {
namespace {

using pi::fe::proto::DeviceMgr;
using Code = ::google::rpc::Code;

using ::testing::_;
using ::testing::AllArgs;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::Truly;

class DeviceMgrPacketIOTest : public DeviceMgrBaseTest {
 public:
  DeviceMgrPacketIOTest() { }

  void SetUp() override {
    auto status = set_pipeline_config(&p4info_proto);
    ASSERT_OK(status);
  }

  p4configv1::P4Info p4info_proto;
};

// Base case for packet-in / packet-out: no special metadata fields
class DeviceMgrPacketIORegTest : public DeviceMgrPacketIOTest { };

TEST_F(DeviceMgrPacketIORegTest, PacketIn) {
  p4v1::PacketIn packet_in;
  bool received = false;
  auto cb_fn = [&packet_in, &received](
      device_id_t, p4v1::StreamMessageResponse *msg, void *) {
    packet_in.CopyFrom(msg->packet());
    received = true;
  };
  mgr.stream_message_response_register_cb(cb_fn, nullptr);
  std::string packet(10, '\xab');
  // we don't need an async task because packetin_inject blocks until the
  // callback is called
  mock->packetin_inject(packet);
  ASSERT_TRUE(received);
  EXPECT_EQ(packet, packet_in.payload());
}

TEST_F(DeviceMgrPacketIORegTest, PacketOut) {
  p4v1::StreamMessageRequest msg;
  auto *packet_out = msg.mutable_packet();
  std::string payload(10, '\xab');
  packet_out->set_payload(payload);
  EXPECT_CALL(*mock, packetout_send(StrEq(payload.c_str()), payload.size()));
  auto status = mgr.stream_message_request_handle(msg);
  EXPECT_EQ(status.code(), Code::OK);
}

using ::testing::WithParamInterface;
using ::testing::Combine;
using ::testing::Range;

namespace {

template<typename T,
         typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
std::string to_binary(T v, int bitwidth, bool canonical = false) {
  std::string s;
  while (bitwidth > 0) {
    s.push_back(static_cast<char>(v % 256));
    v /= 256;
    bitwidth -= 8;
    if (canonical && v == 0) break;
  }
  std::reverse(s.begin(), s.end());
  return s;
}

// iterates over all possible values for a tuple of fields with a given bitwidth
// e.g. (0, 0, 0), (0, 0, 1), (0, 1, 0), (0, 1, 1), (0, 2, 0), ...
template <typename T>
struct ValueIterator {
  ValueIterator(T bitwidths, T steps)
      : bitwidths(bitwidths),
        bounds(bitwidths),
        steps(steps) {
    std::transform(bounds.begin(), bounds.end(), bounds.begin(),
                   [](typename T::value_type x) { return 1 << x; });
  }

  friend struct iterator;
  struct iterator
      : public std::iterator<std::forward_iterator_tag,
                             typename T::value_type> {
    explicit iterator(const ValueIterator<T> *parent, T current = {})
        : parent(parent), current(current) { }

    const T &operator*() const {
      assert(current != parent->bounds && "Invalid iterator dereference.");
      return current;
    }

    const T *operator->() const {
      assert(current != parent->bounds && "Invalid iterator dereference.");
      return &current;
    }

    bool operator==(const iterator &other) const {
      return (parent == other.parent) && (current == other.current);
    }

    bool operator!=(const iterator &other) const {
      return !(*this == other);
    }

    iterator &operator++() {
      const auto &bounds = parent->bounds;
      assert(current != bounds && "Out-of-bounds iterator increment.");
      for (size_t i = current.size(); i > 0; i--) {
        current.at(i - 1) += parent->steps.at(i - 1);
        if (current.at(i - 1) < bounds.at(i - 1)) {
          for (size_t j = i; j < current.size(); j++) current.at(j) = 0;
          return *this;
        } else {
          current.at(i - 1) = bounds.at(i - 1);
        }
      }
      assert(current == bounds);
      return *this;
    }

    const iterator operator++(int) {
      // Use operator++()
      const iterator old(*this);
      ++(*this);
      return old;
    }

    const ValueIterator<T> *parent;
    T current{};
  };

// Bug with some older versions of GCC (e.g. 4.8.2); see
// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=36750
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
  iterator begin() const { return iterator(this); }
#pragma GCC diagnostic pop
  iterator end() const { return iterator(this, bounds); }

  T bitwidths;
  T bounds;
  T steps;
};

}  // namespace

class DeviceMgrPacketIOMetadataTest : public DeviceMgrPacketIOTest {
 public:
  static constexpr int num = 3;
  static constexpr int bw1 = 7;
  static constexpr int bw2 = 7;
  static constexpr int bw3 = 2;
  using VType = std::array<int, num>;

 protected:
  DeviceMgrPacketIOMetadataTest() {
    p4configv1::ControllerPacketMetadata header;
    uint32_t id = 1;
    for (auto bw : bitwidths) {
      auto metadata = header.add_metadata();
      metadata->set_id(id++);
      metadata->set_name("f" + std::to_string(bw));
      metadata->set_bitwidth(bw);
    }
    id = 1;
    for (std::string name : {"packet_in", "packet_out"}) {
      auto pre = header.mutable_preamble();
      pre->set_name(name);
      pre->set_id(id++);
      auto packet_metadata = p4info_proto.add_controller_packet_metadata();
      packet_metadata->CopyFrom(header);
    }
  }

  VType bitwidths{{bw1, bw2, bw3}};
  VType steps{{1, 1, 1}};
};

namespace {

struct BitPattern {
  void push_back(int v, int bw) {
    for (int i = bw - 1; i >= 0; i--) {
      int byte_offset = nbits / 8;
      int bit_offset = nbits % 8;
      if (bit_offset == 0) bits.push_back(0);
      bits[byte_offset] |= (((1 << i) & v) >> i) << (7 - bit_offset);
      nbits++;
    }
  }

  std::string bits{};
  int nbits{0};
};

struct PacketOutMatcher {
 public:
  PacketOutMatcher(const std::string &header, const std::string &payload)
      : header(header), payload(payload) { }

  bool operator()(const char *data, size_t size) const {
    if (header.size() + payload.size() != size) return false;
    return (!header.compare(0, std::string::npos, data, header.size()))
        && (!payload.compare(0, std::string::npos, data + header.size(),
                             payload.size()));
  }

  bool operator()(const std::tuple<const char *, size_t> &t) const {
    return (*this)(std::get<0>(t), std::get<1>(t));
  }

 private:
  const std::string &header;
  const std::string &payload;
};

}  // namespace

TEST_F(DeviceMgrPacketIOMetadataTest, PacketIn) {
  std::string payload(10, '\xab');
  ValueIterator<VType> values(bitwidths, steps);
  p4v1::PacketIn packet_in;
  bool received;
  auto cb_fn = [&packet_in, &received](
      device_id_t, p4v1::StreamMessageResponse *msg, void *) {
    packet_in.CopyFrom(msg->packet());
    received = true;
  };
  mgr.stream_message_response_register_cb(cb_fn, nullptr);
  for (const auto &v : values) {
    received = false;
    BitPattern pattern;
    for (int id = 0; id < num; id++)
      pattern.push_back(v[id], bitwidths[id]);
    std::string packet = pattern.bits + payload;
    mock->packetin_inject(packet);
    ASSERT_TRUE(received);
    EXPECT_EQ(payload, packet_in.payload());
    uint32_t id = 0;
    for (const auto &metadata : packet_in.metadata()) {
      EXPECT_EQ(id + 1, metadata.metadata_id());
      EXPECT_EQ(to_binary(v[id], bitwidths[id], true), metadata.value());
      id++;
    }
  }
}

TEST_F(DeviceMgrPacketIOMetadataTest, PacketOut) {
  std::string payload(10, '\xab');
  ValueIterator<VType> values(bitwidths, steps);
  for (const auto &v : values) {
    p4v1::StreamMessageRequest msg;
    auto *packet_out = msg.mutable_packet();
    packet_out->set_payload(payload);
    BitPattern pattern;
    for (int id = 0; id < num; id++) {
      auto metadata = packet_out->add_metadata();
      metadata->set_metadata_id(id + 1);
      metadata->set_value(to_binary(v[id], bitwidths[id], false));
      pattern.push_back(v[id], bitwidths[id]);
    }
    PacketOutMatcher matcher(pattern.bits, payload);
    EXPECT_CALL(*mock, packetout_send(_, _)).With(AllArgs(Truly(matcher)));
    auto status = mgr.stream_message_request_handle(msg);
    EXPECT_EQ(status.code(), Code::OK);
  }
}

TEST_F(DeviceMgrPacketIOMetadataTest, PacketOutMetadataOutOfOrder) {
  std::string payload(10, '\xab');
  ValueIterator<VType> values(bitwidths, steps);
  for (const auto &v : values) {
    p4v1::StreamMessageRequest msg;
    auto *packet_out = msg.mutable_packet();
    packet_out->set_payload(payload);
    BitPattern pattern;
    for (int id = num - 1; id >= 0; id--) {
      auto metadata = packet_out->add_metadata();
      metadata->set_metadata_id(id + 1);
      metadata->set_value(to_binary(v[id], bitwidths[id], false));
    }
    for (int id = 0; id < num; id++) {
      pattern.push_back(v[id], bitwidths[id]);
    }
    PacketOutMatcher matcher(pattern.bits, payload);
    EXPECT_CALL(*mock, packetout_send(_, _)).With(AllArgs(Truly(matcher)));
    auto status = mgr.stream_message_request_handle(msg);
    EXPECT_EQ(status.code(), Code::OK);
  }
}

TEST_F(DeviceMgrPacketIOMetadataTest, PacketOutCanonicalMetadata) {
  std::string payload(10, '\xab');
  ValueIterator<VType> values(bitwidths, steps);
  for (const auto &v : values) {
    p4v1::StreamMessageRequest msg;
    auto *packet_out = msg.mutable_packet();
    packet_out->set_payload(payload);
    BitPattern pattern;
    for (int id = 0; id < num; id++) {
      auto metadata = packet_out->add_metadata();
      metadata->set_metadata_id(id + 1);
      metadata->set_value(to_binary(v[id], bitwidths[id], true));
      pattern.push_back(v[id], bitwidths[id]);
    }
    PacketOutMatcher matcher(pattern.bits, payload);
    EXPECT_CALL(*mock, packetout_send(_, _)).With(AllArgs(Truly(matcher)));
    auto status = mgr.stream_message_request_handle(msg);
    EXPECT_EQ(status.code(), Code::OK);
  }
}

TEST_F(DeviceMgrPacketIOMetadataTest, PacketOutUnknownMetadata) {
  std::string payload(10, '\xab');
  p4v1::StreamMessageRequest msg;
  auto *packet_out = msg.mutable_packet();
  packet_out->set_payload(payload);
  auto metadata = packet_out->add_metadata();
  metadata->set_metadata_id(num + 1);
  metadata->set_value(to_binary(0, 8));
  auto status = mgr.stream_message_request_handle(msg);
  EXPECT_EQ(status.code(), Code::INVALID_ARGUMENT);
}

// TODO(antonin): not conformant to the P4Runtime spec; according to the spec
// the PacketOut should be dropped if a metadata field is missing.
TEST_F(DeviceMgrPacketIOMetadataTest, PacketOutMissingMetadata) {
  std::string payload(10, '\xab');
  p4v1::StreamMessageRequest msg;
  auto *packet_out = msg.mutable_packet();
  packet_out->set_payload(payload);
  EXPECT_CALL(*mock, packetout_send(_, _));
  auto status = mgr.stream_message_request_handle(msg);
  EXPECT_EQ(status.code(), Code::OK);
}


using ErrorReportingLevel = p4::server::v1::StreamConfig::ErrorReportingLevel;
using ::testing::WithParamInterface;
using ::testing::Values;
using pi::fe::proto::PacketIOMgr;

class PacketIOStreamErrorTest
    : public ProtoFrontendBaseTest,
      public WithParamInterface<ErrorReportingLevel> {
 protected:
  PacketIOStreamErrorTest()
      : mgr(device_id, &server_config) { }

  void SetUp() override {
    p4::server::v1::Config config;
    config.mutable_stream()->set_error_reporting(GetParam());
    server_config.set_config(config);
  }

  p4v1::PacketOut packet_out() const {
    p4v1::PacketOut packet;
    packet.set_payload(std::string(10, '\xab'));
    return packet;
  }

  void check_stream_error(
      const p4v1::PacketOut &packet, int code, bool detailed) {
    p4v1::StreamError stream_error;
    auto status = mgr.packet_out_send(packet, &stream_error);
    EXPECT_EQ(status.code(), code);

    if (GetParam() == p4::server::v1::StreamConfig::DISABLED) {
      EXPECT_EQ(stream_error.canonical_code(), Code::OK);
    } else {
      EXPECT_EQ(stream_error.canonical_code(), code);
      EXPECT_TRUE(stream_error.has_packet_out());
      if (detailed) {
        EXPECT_PROTO_EQ(stream_error.packet_out().packet_out(), packet);
      } else {
        EXPECT_FALSE(stream_error.packet_out().has_packet_out());
      }
    }
  }

  pi::fe::proto::ServerConfigAccessor server_config;
  PacketIOMgr mgr;
};

TEST_P(PacketIOStreamErrorTest, PacketOutUnexpectedMetadata) {
  auto packet = packet_out();

  auto metadata = packet.add_metadata();
  metadata->set_metadata_id(100);
  metadata->set_value(to_binary(0, 8));

  check_stream_error(
      packet,
      Code::INVALID_ARGUMENT,
      GetParam() == p4::server::v1::StreamConfig::DETAILED);
}

TEST_P(PacketIOStreamErrorTest, PacketOutUnkownMetadata) {
  p4configv1::P4Info p4info;
  auto *packet_metadata = p4info.add_controller_packet_metadata();
  auto *pre = packet_metadata->mutable_preamble();
  pre->set_name("packet_out");
  pre->set_id(1);
  mgr.p4_change(p4info);

  auto packet = packet_out();

  auto metadata = packet.add_metadata();
  metadata->set_metadata_id(100);
  metadata->set_value(to_binary(0, 8));

  check_stream_error(
      packet,
      Code::INVALID_ARGUMENT,
      GetParam() == p4::server::v1::StreamConfig::DETAILED);
}

TEST_P(PacketIOStreamErrorTest, PacketOutTargetError) {
  auto packet = packet_out();

  EXPECT_CALL(*mock, packetout_send(_, _))
      .WillOnce(Return(PI_STATUS_TARGET_ERROR));

  check_stream_error(packet, Code::UNKNOWN, false);
}

INSTANTIATE_TEST_SUITE_P(
    StreamErrorLevels, PacketIOStreamErrorTest,
    Values(p4::server::v1::StreamConfig::DISABLED,
           p4::server::v1::StreamConfig::ENABLED,
           p4::server::v1::StreamConfig::DETAILED)
);

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
