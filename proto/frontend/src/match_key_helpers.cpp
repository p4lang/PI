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

#include "match_key_helpers.h"

#include <PI/frontends/cpp/tables.h>
#include <PI/pi.h>

#include <algorithm>  // for std::all_of
#include <string>

#include "google/rpc/code.pb.h"
#include "google/rpc/status.pb.h"
#include "p4/v1/p4runtime.pb.h"

#include "common.h"
#include "report_error.h"

namespace p4v1 = ::p4::v1;

namespace pi {

namespace fe {

namespace proto {

using Code = ::google::rpc::Code;
using p4_id_t = common::p4_id_t;

bool ternary_match_is_dont_care(const p4v1::FieldMatch::Ternary &mf) {
  const auto &mask = mf.mask();
  return std::all_of(mask.begin(), mask.end(),
                     [](std::string::value_type c) { return c == 0; });
}

bool range_match_is_dont_care(const p4v1::FieldMatch::Range &mf) {
  const auto &low = mf.low();
  const auto &high = mf.high();
  auto bitwidth = static_cast<size_t>(low.size() * 8);
  return low == common::range_default_lo(bitwidth) &&
      high == common::range_default_hi(bitwidth);
}

Status parse_match_key(const pi_p4info_t *p4info, p4_id_t table_id,
                       const pi::MatchKey &match_key,
                       p4v1::TableEntry *entry) {
  auto num_match_fields = pi_p4info_table_num_match_fields(
      p4info, table_id);
  auto priority = match_key.get_priority();
  if (priority > 0) entry->set_priority(priority);
  for (size_t j = 0; j < num_match_fields; j++) {
    auto finfo = pi_p4info_table_match_field_info(p4info, table_id, j);
    auto mf = entry->add_match();
    mf->set_field_id(finfo->mf_id);
    switch (finfo->match_type) {
      // For backward-compatibility with the old workflow (P4_14 program ---
      // p4c-bm compiler ---> bmv2 JSON --- converter ---> P4Info), we still
      // support PI_P4INFO_MATCH_TYPE_VALID. The P4_14 valid match type will
      // show up as exact in the P4Info, which is why we set the exact field in
      // the P4Runtime message (to '\x01' for valid and '\x00' for invalid).
      case PI_P4INFO_MATCH_TYPE_VALID:
        {
          auto exact = mf->mutable_exact();
          bool value;
          match_key.get_valid(finfo->mf_id, &value);
          exact->set_value(
              value ? std::string("\x01", 1) : std::string("\x00", 1));
        }
        break;
      case PI_P4INFO_MATCH_TYPE_EXACT:
        {
          auto exact = mf->mutable_exact();
          match_key.get_exact(finfo->mf_id, exact->mutable_value());
        }
        break;
      case PI_P4INFO_MATCH_TYPE_LPM:
        {
          auto lpm = mf->mutable_lpm();
          int pLen;
          match_key.get_lpm(finfo->mf_id, lpm->mutable_value(), &pLen);
          lpm->set_prefix_len(pLen);
          // if prefix length is 0, omit match field
          if (pLen == 0)
            entry->mutable_match()->RemoveLast();
        }
        break;
      case PI_P4INFO_MATCH_TYPE_TERNARY:
        {
          auto ternary = mf->mutable_ternary();
          match_key.get_ternary(finfo->mf_id, ternary->mutable_value(),
                                ternary->mutable_mask());
          // if mask is 0, omit match field
          if (ternary_match_is_dont_care(*ternary))
            entry->mutable_match()->RemoveLast();
        }
        break;
      case PI_P4INFO_MATCH_TYPE_RANGE:
        {
          auto range = mf->mutable_range();
          match_key.get_range(finfo->mf_id, range->mutable_low(),
                              range->mutable_high());
          // if range includes all values, omit match field
          if (range_match_is_dont_care(*range))
            entry->mutable_match()->RemoveLast();
        }
        break;
      default:
        RETURN_ERROR_STATUS(Code::INTERNAL, "Incorrect PI match type");
    }
  }
  RETURN_OK_STATUS();
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
