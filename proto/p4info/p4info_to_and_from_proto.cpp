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

#include <PI/p4info.h>

#include <iostream>
#include <exception>
#include <unordered_map>
#include <string>

#include "p4info_int.h"

#include "p4info_to_and_from_proto.h"

#include "p4/config/p4info.pb.h"

namespace pi {

namespace p4info {

// proto -> p4info

namespace {

// only used internally, not exposed in the header
class read_proto_exception : public std::exception {
 public:
  explicit read_proto_exception(const std::string &msg)
      : msg(msg) { }

  const char* what() const noexcept override {
    return msg.c_str();
  }

 private:
  std::string msg;
};

void import_annotations(const p4::config::Preamble &pre, pi_p4info_t *p4info) {
  auto common = pi_p4info_get_common(p4info, pre.id());
  for (const auto &annotation : pre.annotations())
    p4info_common_push_back_annotation(common, annotation.c_str());
}

void read_actions(const p4::config::P4Info &p4info_proto, pi_p4info_t *p4info) {
  const auto &actions = p4info_proto.actions();
  pi_p4info_action_init(p4info, actions.size());
  for (const auto &action : actions) {
    const auto &pre = action.preamble();
    pi_p4info_action_add(p4info, pre.id(), pre.name().c_str(),
                         action.params().size());
    for (const auto &param : action.params()) {
      pi_p4info_action_add_param(p4info, pre.id(), param.id(),
                                 param.name().c_str(), param.bitwidth());
    }
    import_annotations(pre, p4info);
  }
}

void read_fields(const p4::config::P4Info &p4info_proto, pi_p4info_t *p4info) {
  const auto &header_fields = p4info_proto.header_fields();
  pi_p4info_field_init(p4info, header_fields.size());
  for (const auto &field : header_fields) {
    const auto &pre = field.preamble();
    pi_p4info_field_add(p4info, pre.id(), pre.name().c_str(), field.bitwidth());
    import_annotations(pre, p4info);
  }
}

void read_field_lists(const p4::config::P4Info &p4info_proto,
                      pi_p4info_t *p4info) {
  const auto &header_field_lists = p4info_proto.header_field_lists();
  pi_p4info_field_list_init(p4info, header_field_lists.size());
  for (const auto &field_list : p4info_proto.header_field_lists()) {
    const auto &pre = field_list.preamble();
    pi_p4info_field_list_add(p4info, pre.id(), pre.name().c_str(),
                             field_list.header_field_ids().size());
    for (const auto field_id : field_list.header_field_ids())
      pi_p4info_field_list_add_field(p4info, pre.id(), field_id);
    import_annotations(pre, p4info);
  }
}

void read_tables(const p4::config::P4Info &p4info_proto, pi_p4info_t *p4info) {
  const auto &tables = p4info_proto.tables();
  pi_p4info_table_init(p4info, tables.size());
  for (const auto &table : tables) {
    const auto &pre = table.preamble();
    pi_p4info_table_add(p4info, pre.id(), pre.name().c_str(),
                        table.match_fields().size(), table.action_ids().size());

    for (const auto &mf : table.match_fields()) {
      auto match_type_convert = [&mf]() {
        switch (mf.match_type()) {
          case p4::config::MatchField_MatchType_VALID:
            return PI_P4INFO_MATCH_TYPE_VALID;
          case p4::config::MatchField_MatchType_EXACT:
            return PI_P4INFO_MATCH_TYPE_EXACT;
          case p4::config::MatchField_MatchType_LPM:
            return PI_P4INFO_MATCH_TYPE_LPM;
          case p4::config::MatchField_MatchType_TERNARY:
            return PI_P4INFO_MATCH_TYPE_TERNARY;
          case p4::config::MatchField_MatchType_RANGE:
            return PI_P4INFO_MATCH_TYPE_RANGE;
          default:  // invalid
            throw read_proto_exception("Invalid match type");
        }
      };

      auto mf_id = mf.header_field_id();
      pi_p4info_table_add_match_field(
          p4info, pre.id(), mf_id, pi_p4info_field_name_from_id(p4info, mf_id),
          match_type_convert(), pi_p4info_field_bitwidth(p4info, mf_id));
    }

    for (const auto action_id : table.action_ids())
      pi_p4info_table_add_action(p4info, pre.id(), action_id);

    if (table.const_default_action_id() != PI_INVALID_ID) {
      pi_p4info_table_set_const_default_action(p4info, pre.id(),
                                               table.const_default_action_id());
    }

    if (table.implementation_id() != PI_INVALID_ID) {
      pi_p4info_table_set_implementation(p4info, pre.id(),
                                         table.implementation_id());
    }

    for (const auto &direct_res_id : table.direct_resource_ids())
      pi_p4info_table_add_direct_resource(p4info, pre.id(), direct_res_id);

    // TODO(antonin): size support

    import_annotations(pre, p4info);
  }
}

void read_act_profs(const p4::config::P4Info &p4info_proto,
                    pi_p4info_t *p4info) {
  const auto &action_profiles = p4info_proto.action_profiles();
  pi_p4info_act_prof_init(p4info, action_profiles.size());
  for (const auto &act_prof : action_profiles) {
    const auto &pre = act_prof.preamble();
    pi_p4info_act_prof_add(p4info, pre.id(), pre.name().c_str(),
                           act_prof.with_selector());
    for (const auto table_id : act_prof.table_ids())
      pi_p4info_act_prof_add_table(p4info, pre.id(), table_id);

    // TODO(antonin): size support

    import_annotations(pre, p4info);
  }
}

void read_counters(const p4::config::P4Info &p4info_proto,
                   pi_p4info_t *p4info) {
  const auto &counters = p4info_proto.counters();
  pi_p4info_counter_init(p4info, counters.size());
  for (const auto &counter : counters) {
    const auto &pre = counter.preamble();
    auto unit_convert = [&counter]() {
      switch (counter.unit()) {
        case p4::config::Counter_Unit_BYTES:
          return PI_P4INFO_COUNTER_UNIT_BYTES;
        case p4::config::Counter_Unit_PACKETS:
          return PI_P4INFO_COUNTER_UNIT_PACKETS;
        case p4::config::Counter_Unit_BOTH:
          return PI_P4INFO_COUNTER_UNIT_BOTH;
        default:  // invalid
          throw read_proto_exception("Invalid counter unit");
      }
    };
    pi_p4info_counter_add(p4info, pre.id(), pre.name().c_str(), unit_convert(),
                          counter.size());
    if (counter.direct_table_id() != PI_INVALID_ID) {
      pi_p4info_counter_make_direct(p4info, pre.id(),
                                    counter.direct_table_id());
    }
    import_annotations(pre, p4info);
  }
}

void read_meters(const p4::config::P4Info &p4info_proto, pi_p4info_t *p4info) {
  const auto &meters = p4info_proto.meters();
  pi_p4info_meter_init(p4info, meters.size());
  for (const auto &meter : meters) {
    const auto &pre = meter.preamble();
    auto unit_convert = [&meter]() {
      switch (meter.unit()) {
        case p4::config::Meter_Unit_BYTES:
          return PI_P4INFO_METER_UNIT_BYTES;
        case p4::config::Meter_Unit_PACKETS:
          return PI_P4INFO_METER_UNIT_PACKETS;
        default:  // invalid
          throw read_proto_exception("Invalid meter unit");
      }
    };
    auto type_convert = [&meter]() {
      switch (meter.type()) {
        case p4::config::Meter_Type_COLOR_AWARE:
          return PI_P4INFO_METER_TYPE_COLOR_AWARE;
        case p4::config::Meter_Type_COLOR_UNAWARE:
          return PI_P4INFO_METER_TYPE_COLOR_UNAWARE;
        default:  // invalid
          throw read_proto_exception("Invalid meter type");
      }
    };
    pi_p4info_meter_add(p4info, pre.id(), pre.name().c_str(), unit_convert(),
                        type_convert(), meter.size());
    if (meter.direct_table_id() != PI_INVALID_ID) {
      pi_p4info_meter_make_direct(p4info, pre.id(),
                                    meter.direct_table_id());
    }
    import_annotations(pre, p4info);
  }
}

}  // namespace

bool p4info_proto_reader(const p4::config::P4Info &p4info_proto,
                         pi_p4info_t **p4info) {
  pi_empty_config(p4info);
  try {
    read_actions(p4info_proto, *p4info);
    read_fields(p4info_proto, *p4info);
    read_tables(p4info_proto, *p4info);
    read_act_profs(p4info_proto, *p4info);
    read_counters(p4info_proto, *p4info);
    read_meters(p4info_proto, *p4info);
    read_field_lists(p4info_proto, *p4info);
  } catch (const read_proto_exception &e) {
    std::cerr << e.what() << "\n";
    return false;
  }
  return true;
}

// p4info -> proto

namespace {

template <typename T>
void set_preamble(T *obj, pi_p4_id_t id, const char *name,
                  const pi_p4info_t *p4info) {
  auto pre = obj->mutable_preamble();
  pre->set_id(id);
  pre->set_name(name);
  auto common = pi_p4info_get_common(p4info, id);
  size_t num_annotations;
  auto annotations = p4info_common_annotations(common, &num_annotations);
  for (size_t i = 0; i < num_annotations; i++)
    pre->add_annotations(annotations[i]);
}

void p4info_serialize_actions(const pi_p4info_t *p4info,
                              p4::config::P4Info *p4info_proto) {
  for (auto id = pi_p4info_action_begin(p4info);
       id != pi_p4info_action_end(p4info);
       id = pi_p4info_action_next(p4info, id)) {
    auto action = p4info_proto->add_actions();
    auto name = pi_p4info_action_name_from_id(p4info, id);
    set_preamble(action, id, name, p4info);
    size_t num_params;
    auto param_ids = pi_p4info_action_get_params(p4info, id, &num_params);
    for (size_t i = 0; i < num_params; i++) {
      auto param = action->add_params();
      auto param_id = param_ids[i];
      param->set_id(param_id);
      param->set_name(pi_p4info_action_param_name_from_id(p4info, param_id));
      param->set_bitwidth(pi_p4info_action_param_bitwidth(p4info, param_id));
    }
  }
}

void p4info_serialize_fields(const pi_p4info_t *p4info,
                             p4::config::P4Info *p4info_proto) {
  for (auto id = pi_p4info_field_begin(p4info);
       id != pi_p4info_field_end(p4info);
       id = pi_p4info_field_next(p4info, id)) {
    auto header_field = p4info_proto->add_header_fields();
    auto name = pi_p4info_field_name_from_id(p4info, id);
    set_preamble(header_field, id, name, p4info);
    header_field->set_bitwidth(pi_p4info_field_bitwidth(p4info, id));
  }
}

void p4info_serialize_field_lists(const pi_p4info_t *p4info,
                                  p4::config::P4Info *p4info_proto) {
  for (auto id = pi_p4info_field_list_begin(p4info);
       id != pi_p4info_field_list_end(p4info);
       id = pi_p4info_field_list_next(p4info, id)) {
    auto header_field_list = p4info_proto->add_header_field_lists();
    auto name = pi_p4info_field_list_name_from_id(p4info, id);
    set_preamble(header_field_list, id, name, p4info);
    size_t num_fields;
    auto field_ids = pi_p4info_field_list_get_fields(p4info, id, &num_fields);
    for (size_t i = 0; i < num_fields; i++)
      header_field_list->add_header_field_ids(field_ids[i]);
  }
}

void p4info_serialize_tables(const pi_p4info_t *p4info,
                             p4::config::P4Info *p4info_proto) {
  for (auto id = pi_p4info_table_begin(p4info);
       id != pi_p4info_table_end(p4info);
       id = pi_p4info_table_next(p4info, id)) {
    auto table = p4info_proto->add_tables();
    auto name = pi_p4info_table_name_from_id(p4info, id);
    set_preamble(table, id, name, p4info);

    size_t num_match_fields;
    auto match_field_ids = pi_p4info_table_get_match_fields(p4info, id,
                                                            &num_match_fields);
    for (size_t i = 0; i < num_match_fields; i++) {
      auto mf = table->add_match_fields();
      mf->set_header_field_id(match_field_ids[i]);
      pi_p4info_match_field_info_t info;
      pi_p4info_table_match_field_info(p4info, id, i, &info);
      auto match_type_convert = [&info]() {
        switch (info.match_type) {
          case PI_P4INFO_MATCH_TYPE_VALID:
            return p4::config::MatchField_MatchType_VALID;
          case PI_P4INFO_MATCH_TYPE_EXACT:
            return p4::config::MatchField_MatchType_EXACT;
          case PI_P4INFO_MATCH_TYPE_LPM:
            return p4::config::MatchField_MatchType_LPM;
          case PI_P4INFO_MATCH_TYPE_TERNARY:
            return p4::config::MatchField_MatchType_TERNARY;
          case PI_P4INFO_MATCH_TYPE_RANGE:
            return p4::config::MatchField_MatchType_RANGE;
          default:
            return p4::config::MatchField_MatchType_UNSPECIFIED;
        }
      };
      mf->set_match_type(match_type_convert());
    }

    size_t num_actions;
    auto action_ids = pi_p4info_table_get_actions(p4info, id, &num_actions);
    for (size_t i = 0; i < num_actions; i++)
      table->add_action_ids(action_ids[i]);

    table->set_const_default_action_id(
        pi_p4info_table_get_const_default_action(p4info, id));
    table->set_implementation_id(
        pi_p4info_table_get_implementation(p4info, id));

    size_t num_direct_resources;
    auto direct_res_ids = pi_p4info_table_get_direct_resources(
        p4info, id, &num_direct_resources);
    for (size_t i = 0; i < num_direct_resources; i++)
      table->add_direct_resource_ids(direct_res_ids[i]);

    // TODO(antonin): support size
  }
}

void p4info_serialize_act_profs(const pi_p4info_t *p4info,
                                p4::config::P4Info *p4info_proto) {
  for (auto id = pi_p4info_act_prof_begin(p4info);
       id != pi_p4info_act_prof_end(p4info);
       id = pi_p4info_act_prof_next(p4info, id)) {
    auto act_prof = p4info_proto->add_action_profiles();
    auto name = pi_p4info_act_prof_name_from_id(p4info, id);
    set_preamble(act_prof, id, name, p4info);
    size_t num_tables;
    auto table_ids = pi_p4info_act_prof_get_tables(p4info, id, &num_tables);
    for (size_t i = 0; i < num_tables; i++)
      act_prof->add_table_ids(table_ids[i]);
    act_prof->set_with_selector(pi_p4info_act_prof_has_selector(p4info, id));
    // TODO(antonin): support size
  }
}

void p4info_serialize_counters(const pi_p4info_t *p4info,
                               p4::config::P4Info *p4info_proto) {
  for (auto id = pi_p4info_counter_begin(p4info);
       id != pi_p4info_counter_end(p4info);
       id = pi_p4info_counter_next(p4info, id)) {
    auto counter = p4info_proto->add_counters();
    auto name = pi_p4info_counter_name_from_id(p4info, id);
    set_preamble(counter, id, name, p4info);
    counter->set_direct_table_id(pi_p4info_counter_get_direct(p4info, id));
    auto unit = pi_p4info_counter_get_unit(p4info, id);
    auto unit_convert = [&unit]() {
      switch (unit) {
        case PI_P4INFO_COUNTER_UNIT_BYTES:
          return p4::config::Counter_Unit_BYTES;
        case PI_P4INFO_COUNTER_UNIT_PACKETS:
          return p4::config::Counter_Unit_PACKETS;
        case PI_P4INFO_COUNTER_UNIT_BOTH:
          return p4::config::Counter_Unit_BOTH;
        default:  // invalid
          return p4::config::Counter_Unit_UNSPECIFIED;
      }
    };
    counter->set_unit(unit_convert());
    counter->set_size(pi_p4info_counter_get_size(p4info, id));
  }
}

void p4info_serialize_meters(const pi_p4info_t *p4info,
                             p4::config::P4Info *p4info_proto) {
  for (auto id = pi_p4info_meter_begin(p4info);
       id != pi_p4info_meter_end(p4info);
       id = pi_p4info_meter_next(p4info, id)) {
    auto meter = p4info_proto->add_meters();
    auto name = pi_p4info_meter_name_from_id(p4info, id);
    set_preamble(meter, id, name, p4info);
    meter->set_direct_table_id(pi_p4info_meter_get_direct(p4info, id));
    auto unit = pi_p4info_meter_get_unit(p4info, id);
    auto unit_convert = [&unit]() {
      switch (unit) {
        case PI_P4INFO_METER_UNIT_BYTES:
          return p4::config::Meter_Unit_BYTES;
        case PI_P4INFO_METER_UNIT_PACKETS:
          return p4::config::Meter_Unit_PACKETS;
        default:  // invalid
          return p4::config::Meter_Unit_UNSPECIFIED;
      }
    };
    meter->set_unit(unit_convert());
    auto type = pi_p4info_meter_get_type(p4info, id);
    auto type_convert = [&type]() {
      switch (type) {
        case PI_P4INFO_METER_TYPE_COLOR_AWARE:
          return p4::config::Meter_Type_COLOR_AWARE;
        case PI_P4INFO_METER_TYPE_COLOR_UNAWARE:
          return p4::config::Meter_Type_COLOR_UNAWARE;
        default:  // invalid
          return p4::config::Meter_Type_COLOR_AWARE;
      }
    };
    meter->set_type(type_convert());
    meter->set_size(pi_p4info_meter_get_size(p4info, id));
  }
}

}  // namespace

p4::config::P4Info p4info_serialize_to_proto(const pi_p4info_t *p4info) {
  p4::config::P4Info p4info_proto;
  p4info_serialize_actions(p4info, &p4info_proto);
  p4info_serialize_fields(p4info, &p4info_proto);
  p4info_serialize_field_lists(p4info, &p4info_proto);
  p4info_serialize_tables(p4info, &p4info_proto);
  p4info_serialize_act_profs(p4info, &p4info_proto);
  p4info_serialize_counters(p4info, &p4info_proto);
  p4info_serialize_meters(p4info, &p4info_proto);
  return p4info_proto;
}

}  // namespace p4info

}  // namespace pi
