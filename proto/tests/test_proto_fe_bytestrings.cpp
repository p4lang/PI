/* Copyright 2021 VMware, Inc.
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

#include <gtest/gtest.h>

#include <tuple>

#include "src/common.h"

namespace pi {
namespace proto {
namespace testing {
namespace {

using ::testing::TestWithParam;
using ::testing::Values;

using ::pi::fe::proto::common::bytestring_p4rt_to_pi;
using ::pi::fe::proto::common::bytestring_pi_to_p4rt;

class TestBytestringConversionP4RtToPi
    : public TestWithParam<std::tuple<int, std::string, std::string> > { };

TEST_P(TestBytestringConversionP4RtToPi, convert) {
  auto nbits = std::get<0>(GetParam());
  auto input = std::get<1>(GetParam());
  auto expected_output = std::get<2>(GetParam());
  auto output = bytestring_p4rt_to_pi(input, nbits);
  ASSERT_TRUE(output.ok());
  EXPECT_EQ(output.ValueOrDie(), expected_output);
}

INSTANTIATE_TEST_SUITE_P(
    BytestringConversionsP4RtToPi, TestBytestringConversionP4RtToPi,
    Values(std::make_tuple(
               16, std::string("\x30\x64", 2), std::string("\x30\x64", 2)),
           std::make_tuple(
               16, std::string("\x64", 1), std::string("\x00\x64", 2)),
           std::make_tuple(
               16, std::string("\x00\x64", 2), std::string("\x00\x64", 2)),
           std::make_tuple(
               16, std::string("\x00\x30\x64", 3), std::string("\x30\x64", 2)),
           std::make_tuple(
               12, std::string("\x00\x0f\x64", 3), std::string("\x0f\x64", 2)),
           std::make_tuple(
               12, std::string("\x64", 1), std::string("\x00\x64", 2)),
           std::make_tuple(
               12, std::string("\x0f\x64", 2), std::string("\x0f\x64", 2)))
);

class TestBytestringConversionP4RtToPiErrors
    : public TestWithParam<std::tuple<int, std::string> > { };

TEST_P(TestBytestringConversionP4RtToPiErrors, convert) {
  auto nbits = std::get<0>(GetParam());
  auto input = std::get<1>(GetParam());
  auto output = bytestring_p4rt_to_pi(input, nbits);
  ASSERT_FALSE(output.ok());
}

INSTANTIATE_TEST_SUITE_P(
    BytestringConversionsP4RtToPiErrors, TestBytestringConversionP4RtToPiErrors,
    Values(std::make_tuple(16, std::string("\xab\x30\x64", 3)),
           std::make_tuple(12, std::string("\xff\x30", 2)))
);

class TestBytestringConversionPiToP4Rt
    : public TestWithParam<std::tuple<std::string, std::string> > { };

TEST_P(TestBytestringConversionPiToP4Rt, convert) {
  auto input = std::get<0>(GetParam());
  auto expected_output = std::get<1>(GetParam());
  auto output = bytestring_pi_to_p4rt(input);
  EXPECT_EQ(output, expected_output);
}

TEST_P(TestBytestringConversionPiToP4Rt, convert_cstr) {
  auto input = std::get<0>(GetParam());
  auto expected_output = std::get<1>(GetParam());
  auto output = bytestring_pi_to_p4rt(input.data(), input.size());
  EXPECT_EQ(output, expected_output);
}

INSTANTIATE_TEST_SUITE_P(
    BytestringConversionsPiToP4Rt, TestBytestringConversionPiToP4Rt,
    Values(std::make_tuple(
               std::string("\x30\x64", 2), std::string("\x30\x64", 2)),
           std::make_tuple(
               std::string("\x00\x64", 2), std::string("\x64", 1)))
);

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
