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

#include <gmock/gmock.h>

#include <cstring>
#include <ostream>
#include <string>

#include "p4/v1/p4runtime.pb.h"

#include "PI/int/pi_int.h"
#include "PI/pi.h"
#include "PI/pi_clone.h"

#include "google/rpc/code.pb.h"

#include "matchers.h"

using p4::v1::CounterData;
using p4::v1::MeterConfig;

namespace pi {
namespace proto {
namespace testing {

bool
IsOkMatcher::MatchAndExplain(::google::rpc::Status status,
                             MatchResultListener *listener) const {
  (void) listener;
  return status.code() == ::google::rpc::Code::OK;
}

void
IsOkMatcher::DescribeTo(std::ostream *os) const {
  *os << "is OK";
}

void
IsOkMatcher::DescribeNegationTo(std::ostream *os) const {
  *os << "is not OK";
}

MatchKeyMatcher::MatchKeyMatcher(pi_p4_id_t t_id, const std::string &v)
    : t_id(t_id), v(v) { }

bool
MatchKeyMatcher::MatchAndExplain(const pi_match_key_t *mk,
                                 MatchResultListener *listener) const {
  if (mk->table_id != t_id) {
    *listener << "Invalid table id (expected " << t_id << " but got "
              << mk->table_id << ")";
    return false;
  }
  if (mk->data_size != v.size()) {
    *listener << "Invalid serialized match key size (expected "
              << v.size() << " but got " << mk->data_size << ")";
    return false;
  }
  if (std::memcmp(mk->data, v.data(), v.size())) {
    *listener << "Serialized match key data doesn't match";
    return false;
  }
  return true;
}

void
MatchKeyMatcher::DescribeTo(std::ostream *os) const {
  *os << "is correct match key";
}

void
MatchKeyMatcher::DescribeNegationTo(std::ostream *os) const {
  *os << "is not correct match key";
}

ActionDataMatcher::ActionDataMatcher(pi_p4_id_t a_id, const std::string &v)
    : a_id(a_id), v(v) { }

bool
ActionDataMatcher::MatchAndExplain(const pi_action_data_t *action_data,
                                   MatchResultListener *listener) const {
  if (action_data->action_id != a_id) {
    *listener << "Invalid action id (expected " << a_id << " but got "
              << action_data->action_id << ")";
    return false;
  }
  if (action_data->data_size != v.size()) {
    *listener << "Invalid serialized action data size (expected "
              << v.size() << " but got " << action_data->data_size << ")";
    return false;
  }
  if (std::memcmp(action_data->data, v.data(), v.size())) {
    *listener << "Serialized action data doesn't match";
    return false;
  }
  return true;
}

void
ActionDataMatcher::DescribeTo(std::ostream *os) const {
  *os << "is correct action data";
}

void
ActionDataMatcher::DescribeNegationTo(std::ostream *os) const {
  *os << "is not correct action data";
}

MeterSpecMatcher::MeterSpecMatcher(const MeterConfig &config,
                                   pi_meter_unit_t meter_unit,
                                   pi_meter_type_t meter_type)
    : config(config), meter_unit(meter_unit), meter_type(meter_type) { }

bool
MeterSpecMatcher::MatchAndExplain(const pi_meter_spec_t *spec,
                                  MatchResultListener *listener) const {
  auto cir = static_cast<uint64_t>(config.cir());
  if (spec->cir != cir) {
    *listener << "Invalid CIR (expected " << cir << " but got "
              << spec->cir << ")";
    return false;
  }
  auto cburst = static_cast<uint32_t>(config.cburst());
  if (spec->cburst != cburst) {
    *listener << "Invalid CBurst (expected " << cburst << " but got "
              << spec->cburst << ")";
    return false;
  }
  auto pir = static_cast<uint64_t>(config.pir());
  if (spec->pir != pir) {
    *listener << "Invalid PIR (expected " << pir << " but got "
              << spec->pir << ")";
    return false;
  }
  auto pburst = static_cast<uint32_t>(config.pburst());
  if (spec->pburst != pburst) {
    *listener << "Invalid Pburst (expected " << pburst << " but got "
              << spec->pburst << ")";
    return false;
  }
  if (spec->meter_unit != meter_unit) {
    *listener << "Invalid meter unit";
    return false;
  }
  if (spec->meter_type != meter_type) {
    *listener << "Invalid meter type";
    return false;
  }
  return true;
}

void
MeterSpecMatcher::DescribeTo(std::ostream *os) const {
  *os << "is correct meter spec";
}

void
MeterSpecMatcher::DescribeNegationTo(std::ostream *os) const {
  *os << "is not correct meter spec";
}

CounterDataMatcher::CounterDataMatcher(const CounterData &data,
                                       bool check_bytes, bool check_packets)
    : data(data), check_bytes(check_bytes), check_packets(check_packets) { }

bool
CounterDataMatcher::MatchAndExplain(const pi_counter_data_t *pi_data,
                                    MatchResultListener *listener) const {
  if (check_bytes && !(pi_data->valid & PI_COUNTER_UNIT_BYTES)) {
    *listener << "No valid byte count";
    return false;
  }
  auto byte_count = static_cast<uint64_t>(data.byte_count());
  if (check_bytes && (pi_data->bytes != byte_count)) {
    *listener << "Invalid byte count (expected " << byte_count << " but got "
              << pi_data->bytes << ")";
    return false;
  }
  if (check_packets && !(pi_data->valid & PI_COUNTER_UNIT_PACKETS)) {
    *listener << "No valid packet count";
    return false;
  }
  auto packet_count = static_cast<uint64_t>(data.packet_count());
  if (check_packets && (pi_data->packets != packet_count)) {
    *listener << "Invalid packet count (expected " << packet_count
              << " but got " << pi_data->packets << ")";
    return false;
  }
  return true;
}

void
CounterDataMatcher::DescribeTo(std::ostream *os) const {
  *os << "is correct counter data";
}

void
CounterDataMatcher::DescribeNegationTo(std::ostream *os) const {
  *os << "is not correct counter data";
}

TableEntryMatcher_Base::TableEntryMatcher_Base() = default;

void
TableEntryMatcher_Base::add_direct_meter(pi_p4_id_t meter_id,
                                         const MeterConfig &config,
                                         pi_meter_unit_t meter_unit,
                                         pi_meter_type_t meter_type) {
  meters.emplace(meter_id, MeterSpecMatcher(config, meter_unit, meter_type));
}

void
TableEntryMatcher_Base::add_direct_counter(pi_p4_id_t counter_id,
                                           const CounterData &data,
                                           bool check_bytes,
                                           bool check_packets) {
  counters.emplace(counter_id,
                   CounterDataMatcher(data, check_bytes, check_packets));
}

void
TableEntryMatcher_Base::set_ttl(boost::optional<int64_t> ttl_ns) {
  ttl = ttl_ns;
}

bool
TableEntryMatcher_Base::match_direct(const pi_table_entry_t *t_entry,
                                     MatchResultListener *listener) const {
  auto num_configs = meters.size() + counters.size();
  auto *direct_res_config = t_entry->direct_res_config;
  if (num_configs == 0 && direct_res_config == nullptr) return true;
  if (direct_res_config->num_configs != num_configs) {
    *listener << "Invalid number of direct configs (expected " << num_configs
              << " but got " << direct_res_config->num_configs << ")";
    return false;
  }
  for (size_t i = 0; i < num_configs; i++) {
    auto *config = &direct_res_config->configs[i];
    {
      auto it = meters.find(config->res_id);
      if (it != meters.end()) {
        auto *meter_spec = static_cast<const pi_meter_spec_t *>(
            config->config);
        if (!it->second.MatchAndExplain(meter_spec, listener)) return false;
      }
    }
    {
      auto it = counters.find(config->res_id);
      if (it != counters.end()) {
        auto *counter_data = static_cast<const pi_counter_data_t *>(
            config->config);
        if (!it->second.MatchAndExplain(counter_data, listener)) return false;
      }
    }
  }

  auto *properties = t_entry->entry_properties;
  bool is_ttl_set = pi_entry_properties_is_set(
      properties, PI_ENTRY_PROPERTY_TYPE_TTL);
  if (ttl) {
    if (!is_ttl_set) {
      *listener << "Expected TTL property in table entry";
      return false;
    } else if (*ttl != static_cast<int64_t>(properties->ttl_ns)) {
      *listener << "Expected a TTL value of " << *ttl << " but got "
                << properties->ttl_ns;
      return false;
    }
  } else if (is_ttl_set) {
    *listener << "Unexpected TTL property in table entry";
      return false;
  }

  return true;
}

TableEntryMatcher_Direct::TableEntryMatcher_Direct(pi_p4_id_t a_id,
                                                   const std::string &v)
    : action_data_matcher(a_id, v) { }

bool
TableEntryMatcher_Direct::MatchAndExplain(const pi_table_entry_t *t_entry,
                                          MatchResultListener *listener) const {
  if (t_entry->entry_type != PI_ACTION_ENTRY_TYPE_DATA) {
    *listener << "Invalid table entry type (expected DATA)";
    return false;
  }
  auto *action_data = t_entry->entry.action_data;
  if (!action_data_matcher.MatchAndExplain(action_data, listener))
    return false;
  return match_direct(t_entry, listener);
}

void
TableEntryMatcher_Direct::DescribeTo(std::ostream *os) const {
  *os << "is correct table entry";
}

void
TableEntryMatcher_Direct::DescribeNegationTo(std::ostream *os) const {
  *os << "is not correct table entry";
}

TableEntryMatcher_Indirect::TableEntryMatcher_Indirect(pi_indirect_handle_t h)
    : h(h) { }

bool
TableEntryMatcher_Indirect::MatchAndExplain(
    const pi_table_entry_t *t_entry, MatchResultListener *listener) const {
  if (t_entry->entry_type != PI_ACTION_ENTRY_TYPE_INDIRECT) {
    *listener << "Invalid table entry type (expected INDIRECT)";
    return false;
  }
  if (t_entry->entry.indirect_handle != h) {
    *listener << "Invalid indirect handle (expected " << h << " but got "
              << t_entry->entry.indirect_handle << ")";
    return false;
  }
  return match_direct(t_entry, listener);
}

void
TableEntryMatcher_Indirect::DescribeTo(std::ostream *os) const {
  *os << "is correct indirect table entry";
}

void
TableEntryMatcher_Indirect::DescribeNegationTo(std::ostream *os) const {
  *os << "is not correct indirect table entry";
}

CloneSessionConfigMatcher::CloneSessionConfigMatcher(
    const p4::v1::CloneSessionEntry &session_entry)
    : session_entry(session_entry) { }

bool
CloneSessionConfigMatcher::MatchAndExplain(
    const pi_clone_session_config_t *session_config,
    MatchResultListener *listener) const {
  if (!session_config) {
    *listener << "Config is NULL";
    return false;
  }
  if (session_config->direction != PI_CLONE_DIRECTION_BOTH) {
    *listener << "Invalid direction (expected " << PI_CLONE_DIRECTION_BOTH
              << " but got " << session_config->direction << ")";
    return false;
  }
  if (session_config->eg_port_valid) {
    *listener << "eg_port_valid should be false";
    return false;
  }
  if (!session_config->mc_grp_id_valid) {
    *listener << "mc_grp_id_valid should be true";
    return false;
  }
  if (session_config->copy_to_cpu) {
    *listener << "copy_to_cpu should be false";
    return false;
  }
  if (session_config->max_packet_length !=
      session_entry.packet_length_bytes()) {
    if (session_config->max_packet_length != 0xffff ||
        session_entry.packet_length_bytes() < 0xffff) {
      *listener << "Invalid max_packet_length (expected "
                << session_entry.packet_length_bytes() << " but got "
                << session_config->max_packet_length << ")";
      return false;
    }
  }
  // TODO(antonin): COS?
  return true;
}

void
CloneSessionConfigMatcher::DescribeTo(std::ostream *os) const {
  *os << "is correct clone session config";
}

void
CloneSessionConfigMatcher::DescribeNegationTo(std::ostream *os) const {
  *os << "is not correct clone session config";
}

}  // namespace testing
}  // namespace proto
}  // namespace pi
