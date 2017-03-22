# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# P4 Thrift RPC Input

//:: api_prefix = p4_prefix + "_"

include "res.thrift"

namespace py p4_pd_rpc
namespace cpp p4_pd_rpc
namespace c_glib p4_pd_rpc

typedef i32 EntryHandle_t
typedef i32 MemberHandle_t
typedef i32 GroupHandle_t
typedef binary MacAddr_t
typedef binary IPv6_t

struct ${api_prefix}counter_value_t {
  1: required i64 packets;
  2: required i64 bytes;
}

struct ${api_prefix}counter_flags_t {
  1: required bool read_hw_sync;
}

struct ${api_prefix}packets_meter_spec_t {
  1: required i32 cir_pps;
  2: required i32 cburst_pkts;
  3: required i32 pir_pps;
  4: required i32 pburst_pkts;
  5: required bool color_aware;  // ignored for now
}

struct ${api_prefix}bytes_meter_spec_t {
  1: required i32 cir_kbps;
  2: required i32 cburst_kbits;
  3: required i32 pir_kbps;
  4: required i32 pburst_kbits;
  5: required bool color_aware;  // ignored for now
}

# Match structs

//:: for t_name, t in tables.items():
//::   t_name = get_c_name(t_name)
//::   if not t.key:
/* ${t_name} has no match fields */

//::     continue
//::   #endif
//::   match_params = gen_match_params(t.key)
struct ${api_prefix}${t_name}_match_spec_t {
//::   id = 1
//::   for name, width in match_params:
//::     c_name = get_c_name(name)
//::     type_ = get_thrift_type(width)
  ${id}: required ${type_} ${c_name};
//::   id += 1
//::   #endfor
}

//:: #endfor


# Action structs

//:: for a_name, a in actions.items():
//::   a_name = get_c_name(a_name)
//::   if not a.runtime_data:
/* ${a_name} has no parameters */

//::     continue
//::   #endif
//::   action_params = gen_action_params(a.runtime_data)
struct ${api_prefix}${a_name}_action_spec_t {
//::   id = 1
//::   for name, _, width in action_params:
//::     c_name = get_c_name(name)
//::     type_ = get_thrift_type(width)
  ${id}: required ${type_} ${name};
//::     id += 1
//::   #endfor
}

//:: #endfor


//:: def get_direct_parameter_specs(t, api_prefix):
//::   specs = []
//::   if t.direct_meters:
//::     m = t.direct_meters
//::     if m.unit == m.MeterUnit.PACKETS:
//::       specs += [api_prefix + "packets_meter_spec_t " + m.name + "_spec"]
//::     else:
//::       specs += [api_prefix + "bytes_meter_spec_t " + m.name + "_spec"]
//::     #endif
//::   #endif
//::   return specs
//:: #enddef

service ${p4_prefix} {

    # Table entry add functions
//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type != TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   match_type = t.match_type
//::   has_match_spec = len(t.key) > 0
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["res.SessionHandle_t sess_hdl",
//::               "res.DevTarget_t dev_tgt"]
//::     if has_match_spec:
//::       params += [api_prefix + t_name + "_match_spec_t match_spec"]
//::     #endif
//::     if match_type in {MatchType.TERNARY, MatchType.RANGE}:
//::       params += ["i32 priority"]
//::     #endif
//::     if has_action_spec:
//::       params += [api_prefix + a_name + "_action_spec_t action_spec"]
//::     #endif
//::     if t.support_timeout:
//::       params += ["i32 ttl"]
//::     #endif
//::     params += get_direct_parameter_specs(t, api_prefix)
//::     param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::     param_str = ", ".join(param_list)
//::     name = t_name + "_table_add_with_" + a_name
    EntryHandle_t ${name}(${param_str});
//::   #endfor
//:: #endfor

    # Table entry modify functions
//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type != TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["res.SessionHandle_t sess_hdl",
//::               "byte dev_id",
//::               "EntryHandle_t entry"]
//::     if has_action_spec:
//::       params += [api_prefix + a_name + "_action_spec_t action_spec"]
//::     #endif
//::     params += get_direct_parameter_specs(t, api_prefix)
//::     param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::     param_str = ", ".join(param_list)
//::     name = t_name + "_table_modify_with_" + a_name
    i32 ${name}(${param_str});
//::   #endfor
//:: #endfor

    # Table entry delete functions
//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   t_name = get_c_name(t_name)
//::   name = t_name + "_table_delete"
//::   params = ["res.SessionHandle_t sess_hdl",
//::             "byte dev_id",
//::             "EntryHandle_t entry"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
    i32 ${name}(${param_str});
//:: #endfor

    # Table set default action functions
//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type != TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["res.SessionHandle_t sess_hdl",
//::               "res.DevTarget_t dev_tgt"]
//::     if has_action_spec:
//::       params += [api_prefix + a_name + "_action_spec_t action_spec"]
//::     #endif
//::     params += get_direct_parameter_specs(t, api_prefix)
//::     param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::     param_str = ", ".join(param_list)
//::     name = t_name + "_set_default_action_" + a_name
    EntryHandle_t ${name}(${param_str});
//::   #endfor
//:: #endfor

    # INDIRECT ACTION DATA AND MATCH SELECT

//:: for act_prof_name, act_prof in act_profs.items():
//::   act_prof_name = get_c_name(act_prof_name)
//::   for a_name, a in act_prof.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["res.SessionHandle_t sess_hdl",
//::               "res.DevTarget_t dev_tgt"]
//::     if has_action_spec:
//::       params += [api_prefix + a_name + "_action_spec_t action_spec"]
//::     #endif
//::     param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::     param_str = ", ".join(param_list)
//::     name = act_prof_name + "_add_member_with_" + a_name
    MemberHandle_t ${name}(${param_str});

//::     params = ["res.SessionHandle_t sess_hdl",
//::               "byte dev_id",
//::		   "MemberHandle_t mbr"]
//::     if has_action_spec:
//::       params += [api_prefix + a_name + "_action_spec_t action_spec"]
//::     #endif
//::     param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::     param_str = ", ".join(param_list)
//::     name = act_prof_name + "_modify_member_with_" + a_name
    i32 ${name}(${param_str});
//::   #endfor

//::   params = ["res.SessionHandle_t sess_hdl",
//::             "byte dev_id",
//::             "MemberHandle_t mbr"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
//::   name = act_prof_name + "_del_member"
    i32 ${name}(${param_str});

//::   if not act_prof.with_selector: continue
//::
//::   params = ["res.SessionHandle_t sess_hdl",
//::             "res.DevTarget_t dev_tgt",
//::             "i16 max_grp_size"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
//::   name = act_prof_name + "_create_group"
    GroupHandle_t ${name}(${param_str});

//::   params = ["res.SessionHandle_t sess_hdl",
//::             "byte dev_id",
//::             "GroupHandle_t grp"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
//::   name = act_prof_name + "_del_group"
    i32 ${name}(${param_str});

//::   params = ["res.SessionHandle_t sess_hdl",
//::             "byte dev_id",
//::             "GroupHandle_t grp",
//::             "MemberHandle_t mbr"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
//::   name = act_prof_name + "_add_member_to_group"
    i32 ${name}(${param_str});

//::   params = ["res.SessionHandle_t sess_hdl",
//::             "byte dev_id",
//::             "GroupHandle_t grp",
//::             "MemberHandle_t mbr"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
//::   name = act_prof_name + "_del_member_from_group"
    i32 ${name}(${param_str});

//::   params = ["res.SessionHandle_t sess_hdl",
//::             "byte dev_id",
//::             "GroupHandle_t grp",
//::             "MemberHandle_t mbr"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
//::   name = act_prof_name + "_deactivate_group_member"
    i32 ${name}(${param_str});

//::   params = ["res.SessionHandle_t sess_hdl",
//::             "byte dev_id",
//::             "GroupHandle_t grp",
//::             "MemberHandle_t mbr"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
//::   name = act_prof_name + "_reactivate_group_member"
    i32 ${name}(${param_str});

//:: #endfor

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type == TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   match_type = t.match_type
//::   has_match_spec = len(t.key) > 0
//::   params = ["res.SessionHandle_t sess_hdl",
//::             "res.DevTarget_t dev_tgt"]
//::   if has_match_spec:
//::     params += [api_prefix + t_name + "_match_spec_t match_spec"]
//::   #endif
//::   if match_type in {MatchType.TERNARY, MatchType.RANGE}:
//::     params += ["i32 priority"]
//::   #endif
//::
//::   params_wo = params + ["MemberHandle_t mbr"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params_wo)]
//::   param_str = ", ".join(param_list)
//::   name = t_name + "_add_entry"
    EntryHandle_t ${name}(${param_str});
//::
//::   if t_type != TableType.INDIRECT_WS: continue
//::   params_w = params + ["GroupHandle_t grp"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params_w)]
//::   param_str = ", ".join(param_list)
//::   name = t_name + "_add_entry_with_selector"
    EntryHandle_t ${name}(${param_str});
//:: #endfor

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type == TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   params = ["res.SessionHandle_t sess_hdl",
//::             "res.DevTarget_t dev_tgt"]
//::   params_wo = params + ["MemberHandle_t mbr"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params_wo)]
//::   param_str = ", ".join(param_list)
//::   name = t_name + "_set_default_entry"
    EntryHandle_t ${name}(${param_str});
//::
//::   if t_type != TableType.INDIRECT_WS: continue
//::   params_w = params + ["GroupHandle_t grp"]
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params_w)]
//::   param_str = ", ".join(param_list)
//::   name = t_name + "_set_default_entry_with_selector"
    EntryHandle_t ${name}(${param_str});
//:: #endfor

    # counters

//:: for ca_name, ca in counter_arrays.items():
//::   if ca.is_direct:
//::     name = "counter_read_" + ca_name
    ${api_prefix}counter_value_t ${name}(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:${api_prefix}counter_flags_t flags);
//::     name = "counter_write_" + ca_name
    i32 ${name}(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:EntryHandle_t entry, 4:${api_prefix}counter_value_t counter_value);

//::   else:
//::     name = "counter_read_" + ca_name
    ${api_prefix}counter_value_t ${name}(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:${api_prefix}counter_flags_t flags);
//::     name = "counter_write_" + ca_name
    i32 ${name}(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt, 3:i32 index, 4:${api_prefix}counter_value_t counter_value);

//::   #endif
//:: #endfor

    # meters

//:: for ma_name, ma in meter_arrays.items():
//::   params = ["res.SessionHandle_t sess_hdl",
//::             "res.DevTarget_t dev_tgt"]
//::   if ma.is_direct:
//::     params += ["EntryHandle_t entry"]
//::   else:
//::     params += ["i32 index"]
//::   #endif
//::   if ma.unit == MeterUnit.PACKETS:
//::     params += [api_prefix + "packets_meter_spec_t meter_spec"]
//::   else:
//::     params += [api_prefix + "bytes_meter_spec_t meter_spec"]
//::   #endif
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
//::   name = "meter_set_" + ma_name
    i32 ${name}(${param_str});

//::   params = ["res.SessionHandle_t sess_hdl",
//::             "res.DevTarget_t dev_tgt"]
//::   if ma.is_direct:
//::     params += ["EntryHandle_t entry"]
//::   else:
//::     params += ["i32 index"]
//::   #endif
//::   param_list = [str(count + 1) + ":" + p for count, p in enumerate(params)]
//::   param_str = ", ".join(param_list)
//::   if ma.unit == MeterUnit.PACKETS:
//::     return_type = api_prefix + "packets_meter_spec_t"
//::   else:
//::     return_type = api_prefix + "bytes_meter_spec_t"
//::   #endif
//::   name = "meter_read_" + ma_name
    ${return_type} ${name}(${param_str});

//:: #endfor

//:: for ca_name, ca in counter_arrays.items():
//::   name = "counter_hw_sync_" + ca_name
    i32 ${name}(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt);
//:: #endfor

    # clean all state
//:: name = "clean_all"
    i32 ${name}(1:res.SessionHandle_t sess_hdl, 2:res.DevTarget_t dev_tgt);
}
