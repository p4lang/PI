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

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>

#include <fstream>  // std::ifstream
#include <iostream>
#include <sstream>  // std::stringstream
#include <string>

#include "PI/p4info.h"

#include "p4/config/v1/p4info.pb.h"

#include "PI/proto/p4info_to_and_from_proto.h"

namespace pi {
namespace proto {
namespace testing {
namespace {


class P4InfoProtoConvertFromBmv2JsonTest
    : public ::testing::TestWithParam<const char*> { };

TEST_P(P4InfoProtoConvertFromBmv2JsonTest, Convert) {
  std::cout << "Processing " << GetParam() << "\n";
  std::stringstream ss;
  ss << TESTDATADIR << "/" << GetParam();
  auto input_json = ss.str();

  // first, import bmv2 json to p4info
  pi_p4info_t *p4info;
  pi_status_t status;
  status = pi_add_config_from_file(input_json.c_str(), PI_CONFIG_TYPE_BMV2_JSON,
                                   &p4info);
  ASSERT_EQ(PI_STATUS_SUCCESS, status);

  // export p4info to proto
  const auto p4info_proto_1 = pi::p4info::p4info_serialize_to_proto(p4info);

  // destroy first p4info, which is not needed anymore
  pi_destroy_config(p4info);

  // convert first proto to p4info
  // we have no way of comparing p4info objects unfortunately
  ASSERT_TRUE(pi::p4info::p4info_proto_reader(p4info_proto_1, &p4info));

  // export second p4info to proto
  const auto p4info_proto_2 = pi::p4info::p4info_serialize_to_proto(p4info);

  // destroy second p4info
  pi_destroy_config(p4info);

  // compare proto messages
  using google::protobuf::util::MessageDifferencer;
  ASSERT_TRUE(MessageDifferencer::Equals(p4info_proto_1, p4info_proto_2));
}

const char *input_jsons[] = {
  "simple_router.json",
  "l2_switch.json",
  "ecmp.json",
  "pragmas.json",
  "stats.json",
  "valid.json",
  "act_prof.json"
};
INSTANTIATE_TEST_SUITE_P(P4Iterate,
                         P4InfoProtoConvertFromBmv2JsonTest,
                         ::testing::ValuesIn(input_jsons));

class P4InfoProtoConvertFromProtoTest
    : public ::testing::TestWithParam<const char*> { };

// This test just verifies that the input P4Info Protobuf message can be
// correctly imported. We cannot export the p4info struct back to Protobuf
// format and compare the result to the initial input, as this is a very lossy
// transformation.
TEST_P(P4InfoProtoConvertFromProtoTest, Convert) {
  std::cout << "Processing " << GetParam() << "\n";
  p4::config::v1::P4Info input_proto;
  std::stringstream ss;
  ss << TESTDATADIR << "/" << GetParam();
  auto input_path_str = ss.str();
  std::ifstream is(input_path_str);
  ASSERT_TRUE(is) << "Error while opening protobuf text input file.";
  google::protobuf::io::IstreamInputStream is_(&is);
  auto status = google::protobuf::TextFormat::Parse(&is_, &input_proto);
  ASSERT_TRUE(status) << "Error while importing protobuf text message.";

  // convert proto to p4info
  pi_p4info_t *p4info;
  ASSERT_TRUE(pi::p4info::p4info_proto_reader(input_proto, &p4info));

  // destroy p4info
  pi_destroy_config(p4info);
}

const char *input_protos[] = {
  "customids.p4info.txt"
};
INSTANTIATE_TEST_SUITE_P(P4Iterate,
                         P4InfoProtoConvertFromProtoTest,
                         ::testing::ValuesIn(input_protos));

// Registers whose type cannot be represented (here a struct missing from
// type_info) are imported with a bitwidth of 0, so that the P4Info is still
// accepted.
TEST(P4InfoProtoConvertRegistersTest, Convert) {
  p4::config::v1::P4Info input_proto;
  auto add_register = [&input_proto](pi_p4_id_t id, const char *name,
                                     int32_t size) {
    auto *reg = input_proto.add_registers();
    reg->mutable_preamble()->set_id(id);
    reg->mutable_preamble()->set_name(name);
    reg->set_size(size);
    return reg;
  };
  pi_p4_id_t r_bit_id = (PI_REGISTER_ID << 24) | 1;
  pi_p4_id_t r_struct_id = (PI_REGISTER_ID << 24) | 2;
  auto *r_bit = add_register(r_bit_id, "r_bit", 1024);
  r_bit->mutable_type_spec()->mutable_bitstring()->mutable_bit()
      ->set_bitwidth(160);
  auto *r_struct = add_register(r_struct_id, "r_struct", 16);
  r_struct->mutable_type_spec()->mutable_struct_()->set_name("s_t");

  pi_p4info_t *p4info;
  ASSERT_TRUE(pi::p4info::p4info_proto_reader(input_proto, &p4info));
  EXPECT_EQ(r_bit_id, pi_p4info_register_id_from_name(p4info, "r_bit"));
  EXPECT_EQ(1024u, pi_p4info_register_get_size(p4info, r_bit_id));
  EXPECT_EQ(160u, pi_p4info_register_get_bitwidth(p4info, r_bit_id));
  EXPECT_EQ(r_struct_id, pi_p4info_register_id_from_name(p4info, "r_struct"));
  EXPECT_EQ(16u, pi_p4info_register_get_size(p4info, r_struct_id));
  EXPECT_EQ(0u, pi_p4info_register_get_bitwidth(p4info, r_struct_id));

  // the type of r_struct is lost when exporting back to Protobuf
  const auto output_proto = pi::p4info::p4info_serialize_to_proto(p4info);
  pi_destroy_config(p4info);
  r_struct->clear_type_spec();
  using google::protobuf::util::MessageDifferencer;
  EXPECT_TRUE(MessageDifferencer::Equals(input_proto, output_proto));
}

// The bitwidth of the cells for each type of register supported by PI.
TEST(P4InfoProtoConvertRegistersTest, Types) {
  p4::config::v1::P4Info input_proto;
  pi_p4_id_t next_id = PI_REGISTER_ID << 24;
  auto add_register = [&input_proto, &next_id](const char *name) {
    auto *reg = input_proto.add_registers();
    reg->mutable_preamble()->set_id(++next_id);
    reg->mutable_preamble()->set_name(name);
    reg->set_size(8);
    return reg->mutable_type_spec();
  };
  auto *type_info = input_proto.mutable_type_info();

  add_register("r_int")->mutable_bitstring()->mutable_int_()->set_bitwidth(12);
  add_register("r_varbit")->mutable_bitstring()->mutable_varbit()
      ->set_max_bitwidth(32);
  add_register("r_bool")->mutable_bool_();
  add_register("r_error")->mutable_error();
  type_info->mutable_error()->add_members("NoError");

  add_register("r_serializable_enum")->mutable_serializable_enum()
      ->set_name("color_t");
  auto &color_t = (*type_info->mutable_serializable_enums())["color_t"];
  color_t.mutable_underlying_type()->set_bitwidth(8);
  auto *red = color_t.add_members();
  red->set_name("RED");
  red->set_value(std::string("\x01", 1));

  add_register("r_enum")->mutable_enum_()->set_name("shape_t");
  auto &shape_t = (*type_info->mutable_enums())["shape_t"];
  shape_t.add_members()->set_name("CIRCLE");
  shape_t.add_members()->set_name("SQUARE");

  add_register("r_new_type")->mutable_new_type()->set_name("id_t");
  (*type_info->mutable_new_types())["id_t"].mutable_original_type()
      ->mutable_bitstring()->mutable_bit()->set_bitwidth(20);

  add_register("r_translated_type")->mutable_new_type()->set_name("port_t");
  (*type_info->mutable_new_types())["port_t"].mutable_translated_type()
      ->set_sdn_bitwidth(32);

  add_register("r_nested_new_type")->mutable_new_type()->set_name("id2_t");
  (*type_info->mutable_new_types())["id2_t"].mutable_original_type()
      ->mutable_new_type()->set_name("id_t");

  // header h_t { bit<8> a; int<4> b; }
  auto add_field = [](p4::config::v1::P4HeaderTypeSpec *header,
                      const char *name) {
    auto *member = header->add_members();
    member->set_name(name);
    return member->mutable_type_spec();
  };
  auto &h_t = (*type_info->mutable_headers())["h_t"];
  add_field(&h_t, "a")->mutable_bit()->set_bitwidth(8);
  add_field(&h_t, "b")->mutable_int_()->set_bitwidth(4);
  add_register("r_header")->mutable_header()->set_name("h_t");
  auto &varbit_h_t = (*type_info->mutable_headers())["varbit_h_t"];
  add_field(&varbit_h_t, "a")->mutable_varbit()->set_max_bitwidth(8);
  add_register("r_varbit_header")->mutable_header()->set_name("varbit_h_t");

  // header_union u_t { h_t h1; h_t h2; }
  auto &u_t = (*type_info->mutable_header_unions())["u_t"];
  for (const char *name : {"h1", "h2"}) {
    auto *member = u_t.add_members();
    member->set_name(name);
    member->mutable_header()->set_name("h_t");
  }
  add_register("r_header_union")->mutable_header_union()->set_name("u_t");

  auto *stack = add_register("r_header_stack")->mutable_header_stack();
  stack->mutable_header()->set_name("h_t");
  stack->set_size(4);
  auto *union_stack =
      add_register("r_header_union_stack")->mutable_header_union_stack();
  union_stack->mutable_header_union()->set_name("u_t");
  union_stack->set_size(3);

  // struct s_t { bool a; h_t b; tuple<color_t, id_t> c; }
  auto &s_t = (*type_info->mutable_structs())["s_t"];
  auto add_member = [&s_t](const char *name) {
    auto *member = s_t.add_members();
    member->set_name(name);
    return member->mutable_type_spec();
  };
  add_member("a")->mutable_bool_();
  add_member("b")->mutable_header()->set_name("h_t");
  auto *c = add_member("c")->mutable_tuple();
  c->add_members()->mutable_serializable_enum()->set_name("color_t");
  c->add_members()->mutable_new_type()->set_name("id_t");
  add_register("r_struct")->mutable_struct_()->set_name("s_t");

  // a struct with a member which cannot be represented
  auto &bad_s_t = (*type_info->mutable_structs())["bad_s_t"];
  auto *bad_member = bad_s_t.add_members();
  bad_member->set_name("a");
  bad_member->mutable_type_spec()->mutable_new_type()->set_name("port_t");
  add_register("r_bad_struct")->mutable_struct_()->set_name("bad_s_t");

  // an empty struct
  (*type_info->mutable_structs())["empty_t"];
  add_register("r_empty_struct")->mutable_struct_()->set_name("empty_t");

  // a struct which contains itself
  auto &loop_t = (*type_info->mutable_structs())["loop_t"];
  auto *loop_member = loop_t.add_members();
  loop_member->set_name("a");
  loop_member->mutable_type_spec()->mutable_struct_()->set_name("loop_t");
  add_register("r_loop")->mutable_struct_()->set_name("loop_t");

  // structs fan_<i> { fan_<i+1> a; fan_<i+1> b; }, fan_19 having 2 bit<1>
  // members: fan_0 has 2^20 bit<1> leaves, too many types to visit, and fan_10
  // has 2^10
  for (int i = 0; i < 20; i++) {
    auto &fan = (*type_info->mutable_structs())["fan_" + std::to_string(i)];
    for (const char *name : {"a", "b"}) {
      auto *member = fan.add_members();
      member->set_name(name);
      auto *member_type = member->mutable_type_spec();
      if (i == 19) {
        member_type->mutable_bitstring()->mutable_bit()->set_bitwidth(1);
      } else {
        member_type->mutable_struct_()->set_name(
            "fan_" + std::to_string(i + 1));
      }
    }
  }
  add_register("r_fan_out")->mutable_struct_()->set_name("fan_0");
  add_register("r_small_fan_out")->mutable_struct_()->set_name("fan_10");

  // types missing from type_info
  add_register("r_unknown_enum")->mutable_enum_()->set_name("unknown_t");
  add_register("r_unknown_new_type")->mutable_new_type()
      ->set_name("unknown_t");
  add_register("r_unknown_header")->mutable_header()->set_name("unknown_t");

  pi_p4info_t *p4info;
  ASSERT_TRUE(pi::p4info::p4info_proto_reader(input_proto, &p4info));
  auto bitwidth = [p4info](const char *name) {
    auto id = pi_p4info_register_id_from_name(p4info, name);
    return pi_p4info_register_get_bitwidth(p4info, id);
  };
  EXPECT_EQ(12u, bitwidth("r_int"));
  // the dynamic bitwidth on 32 bits, followed by the value
  EXPECT_EQ(64u, bitwidth("r_varbit"));
  EXPECT_EQ(1u, bitwidth("r_bool"));
  EXPECT_EQ(32u, bitwidth("r_error"));
  EXPECT_EQ(8u, bitwidth("r_serializable_enum"));
  // p4c uses bit<32> for enums without an underlying type
  EXPECT_EQ(32u, bitwidth("r_enum"));
  EXPECT_EQ(20u, bitwidth("r_new_type"));
  EXPECT_EQ(0u, bitwidth("r_translated_type"));
  EXPECT_EQ(20u, bitwidth("r_nested_new_type"));
  // the validity bit, followed by the fields
  EXPECT_EQ(13u, bitwidth("r_header"));
  EXPECT_EQ(0u, bitwidth("r_varbit_header"));
  EXPECT_EQ(26u, bitwidth("r_header_union"));
  EXPECT_EQ(52u, bitwidth("r_header_stack"));
  EXPECT_EQ(78u, bitwidth("r_header_union_stack"));
  EXPECT_EQ(1u + 13u + 8u + 20u, bitwidth("r_struct"));
  EXPECT_EQ(0u, bitwidth("r_bad_struct"));
  EXPECT_EQ(0u, bitwidth("r_empty_struct"));
  EXPECT_EQ(0u, bitwidth("r_loop"));
  EXPECT_EQ(0u, bitwidth("r_fan_out"));
  EXPECT_EQ(1024u, bitwidth("r_small_fan_out"));
  EXPECT_EQ(0u, bitwidth("r_unknown_enum"));
  EXPECT_EQ(0u, bitwidth("r_unknown_new_type"));
  EXPECT_EQ(0u, bitwidth("r_unknown_header"));

  // the cells are exported as bit<W>
  const auto output_proto = pi::p4info::p4info_serialize_to_proto(p4info);
  pi_destroy_config(p4info);
  ASSERT_LT(0, output_proto.registers_size());
  const auto &r_int = output_proto.registers(0);
  EXPECT_EQ("r_int", r_int.preamble().name());
  EXPECT_EQ(12, r_int.type_spec().bitstring().bit().bitwidth());
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
