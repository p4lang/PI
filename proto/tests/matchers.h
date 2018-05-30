/* Copyright 2013-present Barefoot Networks, Inc.
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

#ifndef PROTO_TESTS_MATCHERS_H_
#define PROTO_TESTS_MATCHERS_H_

#include <gmock/gmock.h>

#include <iosfwd>
#include <string>
#include <unordered_map>

#include "p4/v1/p4runtime.pb.h"

#include "PI/pi.h"

namespace pi {
namespace proto {
namespace testing {

using ::testing::MakeMatcher;
using ::testing::Matcher;
using ::testing::MatcherInterface;
using ::testing::MatchResultListener;

// This is a very verbose matcher but it has the advantage to print convenient
// error messages. Not sure I could achieve such a nice result by only using
// googlemock base matchers (e.g. Field...)
class MatchKeyMatcher : public MatcherInterface<const pi_match_key_t *> {
 public:
  MatchKeyMatcher(pi_p4_id_t t_id, const std::string &v);

  bool MatchAndExplain(const pi_match_key_t *mk,
                       MatchResultListener *listener) const override;

  void DescribeTo(std::ostream *os) const override;

  void DescribeNegationTo(std::ostream *os) const override;

 private:
  pi_p4_id_t t_id;
  std::string v;
};

inline Matcher<const pi_match_key_t *> CorrectMatchKey(
    pi_p4_id_t t_id, const std::string &v) {
  return MakeMatcher(new MatchKeyMatcher(t_id, v));
}

class ActionDataMatcher : public MatcherInterface<const pi_action_data_t *> {
 public:
  ActionDataMatcher(pi_p4_id_t a_id, const std::string &v);

  bool MatchAndExplain(const pi_action_data_t *action_data,
                       MatchResultListener *listener) const override;

  void DescribeTo(std::ostream *os) const override;

  void DescribeNegationTo(std::ostream *os) const override;

 private:
  pi_p4_id_t a_id;
  std::string v;
};

inline Matcher<const pi_action_data_t *> CorrectActionData(
    pi_p4_id_t a_id, const std::string &v) {
  return MakeMatcher(new ActionDataMatcher(a_id, v));
}

class MeterSpecMatcher : public MatcherInterface<const pi_meter_spec_t *> {
 public:
  MeterSpecMatcher(const p4::v1::MeterConfig &config,
                   pi_meter_unit_t meter_unit,
                   pi_meter_type_t meter_type);

  bool MatchAndExplain(const pi_meter_spec_t *spec,
                       MatchResultListener *listener) const override;

  void DescribeTo(std::ostream *os) const override;

  void DescribeNegationTo(std::ostream *os) const override;

 private:
  p4::v1::MeterConfig config;
  pi_meter_unit_t meter_unit;
  pi_meter_type_t meter_type;
};

inline Matcher<const pi_meter_spec_t *> CorrectMeterSpec(
    const p4::v1::MeterConfig &config,
    pi_meter_unit_t meter_unit, pi_meter_type_t meter_type) {
  return MakeMatcher(new MeterSpecMatcher(config, meter_unit, meter_type));
}

class CounterDataMatcher : public MatcherInterface<const pi_counter_data_t *> {
 public:
  CounterDataMatcher(const p4::v1::CounterData &data,
                     bool check_bytes, bool check_packets);

  bool MatchAndExplain(const pi_counter_data_t *pi_data,
                       MatchResultListener *listener) const override;

  void DescribeTo(std::ostream *os) const override;

  void DescribeNegationTo(std::ostream *os) const override;

 private:
  p4::v1::CounterData data;
  bool check_bytes;
  bool check_packets;
};

inline Matcher<const pi_counter_data_t *> CorrectCounterData(
    const p4::v1::CounterData &data, bool check_bytes, bool check_packets) {
  return MakeMatcher(new CounterDataMatcher(data, check_bytes, check_packets));
}

class TableEntryMatcher_Base {
 public:
  void add_direct_meter(pi_p4_id_t meter_id,
                        const p4::v1::MeterConfig &config,
                        pi_meter_unit_t meter_unit,
                        pi_meter_type_t meter_type);

  void add_direct_counter(pi_p4_id_t counter_id,
                          const p4::v1::CounterData &data,
                          bool check_bytes, bool check_packets);

 protected:
  TableEntryMatcher_Base();

  bool match_direct(const pi_table_entry_t *t_entry,
                    MatchResultListener *listener) const;

  std::unordered_map<pi_p4_id_t, MeterSpecMatcher> meters;
  std::unordered_map<pi_p4_id_t, CounterDataMatcher> counters;
};

class TableEntryMatcher_Direct
    : public TableEntryMatcher_Base,
      public MatcherInterface<const pi_table_entry_t *> {
 public:
  TableEntryMatcher_Direct(pi_p4_id_t a_id, const std::string &v);

  bool MatchAndExplain(const pi_table_entry_t *t_entry,
                       MatchResultListener *listener) const override;

  void DescribeTo(std::ostream *os) const override;

  void DescribeNegationTo(std::ostream *os) const override;

 private:
  ActionDataMatcher action_data_matcher;
};

inline Matcher<const pi_table_entry_t *> CorrectTableEntryDirect(
    pi_p4_id_t a_id, const std::string &v) {
  return MakeMatcher(new TableEntryMatcher_Direct(a_id, v));
}

class TableEntryMatcher_Indirect
    : public TableEntryMatcher_Base,
      public MatcherInterface<const pi_table_entry_t *> {
 public:
  explicit TableEntryMatcher_Indirect(pi_indirect_handle_t h);

  bool MatchAndExplain(const pi_table_entry_t *t_entry,
                       MatchResultListener *listener) const override;

  void DescribeTo(std::ostream *os) const override;

  void DescribeNegationTo(std::ostream *os) const override;

 private:
  pi_indirect_handle_t h;
};

inline Matcher<const pi_table_entry_t *> CorrectTableEntryIndirect(
    pi_indirect_handle_t h) {
  return MakeMatcher(new TableEntryMatcher_Indirect(h));
}

}  // namespace testing
}  // namespace proto
}  // namespace pi

#endif  // PROTO_TESTS_MATCHERS_H_
