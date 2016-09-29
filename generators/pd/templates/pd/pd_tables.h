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

#ifndef _P4_PD_TABLES_H_
#define _P4_PD_TABLES_H_

#include ${target_common_h}

#include "pd_types.h"

#ifdef __cplusplus
extern "C" {
#endif

//:: def get_direct_parameter_specs(t):
//::   specs = []
//::   if t.direct_meters:
//::     m = t.direct_meters
//::     if m.unit == m.MeterUnit.PACKETS:
//::       specs += ["p4_pd_packets_meter_spec_t *" + m.name + "_spec"]
//::     else:
//::       specs += ["p4_pd_bytes_meter_spec_t *" + m.name + "_spec"]
//::     #endif
//::   #endif
//::   return specs
//:: #enddef

/* ADD ENTRIES */

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type != TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   match_type = t.match_type
//::   has_match_spec = len(t.key) > 0
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["p4_pd_sess_hdl_t sess_hdl",
//::               "p4_pd_dev_target_t dev_tgt"]
//::     if has_match_spec:
//::       params += [pd_prefix + t_name + "_match_spec_t *match_spec"]
//::     #endif
//::     if match_type in {MatchType.TERNARY, MatchType.RANGE}:
//::       params += ["int priority"]
//::     #endif
//::     if has_action_spec:
//::       params += [pd_prefix + a_name + "_action_spec_t *action_spec"]
//::     #endif
//::     if t.support_timeout:
//::       params += ["uint32_t ttl"]
//::     #endif
//::     params += get_direct_parameter_specs(t)
//::     params += ["p4_pd_entry_hdl_t *entry_hdl"]
//::     param_str = ",\n ".join(params)
//::     name = pd_prefix + t_name + "_table_add_with_" + a_name
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   #endfor
//:: #endfor

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type == TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   match_type = t.match_type
//::   has_match_spec = len(t.key) > 0
//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "p4_pd_dev_target_t dev_tgt"]
//::   if has_match_spec:
//::     params += [pd_prefix + t_name + "_match_spec_t *match_spec"]
//::   #endif
//::   if match_type in {MatchType.TERNARY, MatchType.RANGE}:
//::     params += ["int priority"]
//::   #endif
//::
//::   params_indirect = params + ["p4_pd_mbr_hdl_t mbr_hdl", "p4_pd_entry_hdl_t *entry_hdl"]
//::   param_str = ",\n ".join(params_indirect)
//::   name = pd_prefix + t_name + "_add_entry"
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   if t_type != TableType.INDIRECT_WS: continue
//::   params_indirect_ws = params + ["p4_pd_grp_hdl_t grp_hdl", "p4_pd_entry_hdl_t *entry_hdl"]
//::   param_str = ",\n ".join(params_indirect_ws)
//::   name = pd_prefix + t_name + "_add_entry_with_selector"
p4_pd_status_t
${name}
(
 ${param_str}
);

//:: #endfor

/* DELETE ENTRIES */

//:: for t_name, t in tables.items():
//::   t_name = get_c_name(t_name)
//::   name = pd_prefix + t_name + "_table_delete"
p4_pd_status_t
${name}
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
);

//:: #endfor

/* MODIFY ENTRIES */

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type != TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["p4_pd_sess_hdl_t sess_hdl",
//::               "uint8_t dev_id",
//::               "p4_pd_entry_hdl_t entry_hdl"]
//::     if has_action_spec:
//::       params += [pd_prefix + a_name + "_action_spec_t *action_spec"]
//::     #endif
//::     params += get_direct_parameter_specs(t)
//::     param_str = ",\n ".join(params)
//::     name = pd_prefix + t_name + "_table_modify_with_" + a_name
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   #endfor
//:: #endfor


/* SET DEFAULT_ACTION */

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type != TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["p4_pd_sess_hdl_t sess_hdl",
//::               "p4_pd_dev_target_t dev_tgt"]
//::     if has_action_spec:
//::       params += [pd_prefix + a_name + "_action_spec_t *action_spec"]
//::     #endif
//::     # ignored for now
//::     params += get_direct_parameter_specs(t)
//::     params += ["p4_pd_entry_hdl_t *entry_hdl"]
//::     param_str = ",\n ".join(params)
//::     name = pd_prefix + t_name + "_set_default_action_" + a_name
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   #endfor
//:: #endfor

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type == TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "p4_pd_dev_target_t dev_tgt"]
//::
//::   params_indirect = params + ["p4_pd_mbr_hdl_t mbr_hdl", "p4_pd_entry_hdl_t *entry_hdl"]
//::   param_str = ",\n ".join(params_indirect)
//::   name = pd_prefix + t_name + "_set_default_entry"
p4_pd_status_t
${name}
(
 ${param_str}
);
//::   if t_type != TableType.INDIRECT_WS: continue
//::   params_indirect_ws = params + ["p4_pd_grp_hdl_t grp_hdl", "p4_pd_entry_hdl_t *entry_hdl"]
//::   param_str = ",\n ".join(params_indirect_ws)
//::   name = pd_prefix + t_name + "_set_default_entry_with_selector"
p4_pd_status_t
${name}
(
 ${param_str}
);

//:: #endfor

//:: for act_prof_name, act_prof in act_profs.items():
//::   act_prof_name = get_c_name(act_prof_name)
//::   for a_name, a in act_prof.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["p4_pd_sess_hdl_t sess_hdl",
//::               "p4_pd_dev_target_t dev_tgt"]
//::     if has_action_spec:
//::       params += [pd_prefix + a_name + "_action_spec_t *action_spec"]
//::     #endif
//::     params += ["p4_pd_mbr_hdl_t *mbr_hdl"]
//::     param_str = ",\n ".join(params)
//::     name = pd_prefix + act_prof_name + "_add_member_with_" + a_name
p4_pd_status_t
${name}
(
 ${param_str}
);

//::     params = ["p4_pd_sess_hdl_t sess_hdl",
//::               "uint8_t dev_id",
//::               "p4_pd_mbr_hdl_t mbr_hdl"]
//::     if has_action_spec:
//::       params += [pd_prefix + a_name + "_action_spec_t *action_spec"]
//::     #endif
//::     param_str = ",\n ".join(params)
//::     name = pd_prefix + act_prof_name + "_modify_member_with_" + a_name
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   #endfor
//::
//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "uint8_t dev_id",
//::             "p4_pd_mbr_hdl_t mbr_hdl"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + act_prof_name + "_del_member"
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   if not act_prof.with_selector: continue
//::
//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "p4_pd_dev_target_t dev_tgt",
//::             "uint16_t max_grp_size",
//::             "p4_pd_grp_hdl_t *grp_hdl"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + act_prof_name + "_create_group"
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "uint8_t dev_id",
//::             "p4_pd_grp_hdl_t grp_hdl"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + act_prof_name + "_del_group"
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "uint8_t dev_id",
//::             "p4_pd_mbr_hdl_t mbr_hdl",
//::             "p4_pd_grp_hdl_t grp_hdl"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + act_prof_name + "_add_member_to_group"
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "uint8_t dev_id",
//::             "p4_pd_grp_hdl_t grp_hdl",
//::             "p4_pd_mbr_hdl_t mbr_hdl"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + act_prof_name + "_del_member_from_group"
p4_pd_status_t
${name}
(
 ${param_str}
);

//:: #endfor


/* DIRECT COUNTERS */

//:: for t_name, t in tables.items():
//::   if not t.with_counters: continue
//::   t_name = get_c_name(t_name)
//::   name = pd_prefix + t_name + "_read_counter"
p4_pd_status_t
${name}
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_entry_hdl_t entry_hdl,
 p4_pd_counter_value_t *counter_value
);

//::   name = pd_prefix + t_name + "_reset_counters"
p4_pd_status_t
${name}
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt
);

//:: #endfor

//:: for t_name, t in tables.items():
//:: if not t.support_timeout: continue
//::   p4_pd_enable_hit_state_scan = "_".join([pd_prefix[:-1], t_name, "enable_hit_state_scan"])
//::   p4_pd_get_hit_state = "_".join([pd_prefix[:-1], t_name, "get_hit_state"])
//::   p4_pd_set_entry_ttl = "_".join([pd_prefix[:-1], t_name, "set_entry_ttl"])
//::   p4_pd_enable_entry_timeout = "_".join([pd_prefix[:-1], t_name, "enable_entry_timeout"])
p4_pd_status_t
${p4_pd_enable_hit_state_scan}(p4_pd_sess_hdl_t sess_hdl, uint32_t scan_interval);

p4_pd_status_t
${p4_pd_get_hit_state}(p4_pd_sess_hdl_t sess_hdl, p4_pd_entry_hdl_t entry_hdl, p4_pd_hit_state_t *hit_state);

p4_pd_status_t
${p4_pd_set_entry_ttl}(p4_pd_sess_hdl_t sess_hdl, p4_pd_entry_hdl_t entry_hdl, uint32_t ttl);

p4_pd_status_t
${p4_pd_enable_entry_timeout}(p4_pd_sess_hdl_t sess_hdl,
			      p4_pd_notify_timeout_cb cb_fn,
			      uint32_t max_ttl,
			      void *client_data);
//:: #endfor

/* Clean all state */
//:: name = pd_prefix + "clean_all"
p4_pd_status_t
${name}(p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt);

#ifdef __cplusplus
}
#endif

#endif
