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

#include "pd/pd_tables.h"
#include "pd_utils.h"

#include <PI/pi.h>
#include <PI/frontends/generic/pi.h>
// TODO(antonin): removed this dependency (comes from action param ids)
#include <PI/int/pi_int.h>

#define PD_DEBUG 1

// default is disabled
// #define HOST_BYTE_ORDER_CALLER


__attribute__ ((unused))
static void get_f_1B(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                     pi_p4_id_t fid, uint8_t f, int nbytes, pi_netv_t *netv) {
  (void) nbytes;
  pi_status_t rc = pi_getnetv_u8(p4info, parent_id, fid, f, netv);
  assert(rc == PI_STATUS_SUCCESS);
}

__attribute__ ((unused))
static void get_f_2B(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                     pi_p4_id_t fid, uint16_t f, int nbytes, pi_netv_t *netv) {
  (void) nbytes;
  pi_status_t rc = pi_getnetv_u16(p4info, parent_id, fid, f, netv);
  assert(rc == PI_STATUS_SUCCESS);
}

__attribute__ ((unused))
static void get_f_3B(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                     pi_p4_id_t fid, uint32_t f, int nbytes, pi_netv_t *netv) {
  (void) nbytes;
  pi_status_t rc = pi_getnetv_u32(p4info, parent_id, fid, f, netv);
  assert(rc == PI_STATUS_SUCCESS);
}

__attribute__ ((unused))
static void get_f_4B(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                     pi_p4_id_t fid, uint32_t f, int nbytes, pi_netv_t *netv) {
  (void) nbytes;
  pi_status_t rc = pi_getnetv_u32(p4info, parent_id, fid, f, netv);
  assert(rc == PI_STATUS_SUCCESS);
}

__attribute__ ((unused))
static void get_f_XB(const pi_p4info_t *p4info, pi_p4_id_t parent_id,
                     pi_p4_id_t fid, uint8_t *f, int nbytes, pi_netv_t *netv) {
  char *f_ = (char *) f;
  pi_status_t rc = pi_getnetv_ptr(p4info, parent_id, fid, f_, nbytes, netv);
  assert(rc == PI_STATUS_SUCCESS);
}

//:: for t_name, t in tables.items():
//::   if not t.key: continue
//::   t_name = get_c_name(t_name)
static void build_key_${t_name} (
    const pi_p4info_t *p4info, pi_match_key_t *mk, ${pd_prefix}${t_name}_match_spec_t *match_spec
) {
  pi_match_key_init(mk);

  pi_status_t rc; (void) rc;
  pi_netv_t netv_1, netv_2; (void) netv_1; (void) netv_2;

//::   for field_name, fid, field_match_type, field_bw in t.key:
//::     field_name = get_c_name(field_name)
//::     nbytes = (field_bw + 7) / 8
//::     fnB = nbytes if nbytes <= 4 else 'X'
//::     if field_match_type == MatchType.EXACT:
  get_f_${fnB}B(p4info, ${t.id_}, ${fid}, match_spec->${field_name}, ${nbytes}, &netv_1);
  rc = pi_match_key_exact_set(mk, &netv_1);
  assert(rc == PI_STATUS_SUCCESS);
//::     elif field_match_type == MatchType.LPM:
  get_f_${fnB}B(p4info, ${t.id_}, ${fid}, match_spec->${field_name}, ${nbytes}, &netv_1);
  rc = pi_match_key_lpm_set(mk, &netv_1, match_spec->${field_name}_prefix_length);
  assert(rc == PI_STATUS_SUCCESS);
//::     elif field_match_type == MatchType.TERNARY:
  get_f_${fnB}B(p4info, ${t.id_}, ${fid}, match_spec->${field_name}, ${nbytes}, &netv_1);
  get_f_${fnB}B(p4info, ${t.id_}, ${fid}, match_spec->${field_name}_mask, ${nbytes}, &netv_1);
  rc = pi_match_key_ternary_set(mk, &netv_1, &netv_2);
  assert(rc == PI_STATUS_SUCCESS);
//::     elif field_match_type == MatchType.VALID:
  rc = pi_getnetv_u8(p4info, ${t.id_}, ${fid}, (uint8_t) (match_spec->${field_name} != 0), &netv_1);
  assert(rc == PI_STATUS_SUCCESS);
  rc = pi_match_key_exact_set(mk, &netv_1);
  assert(rc == PI_STATUS_SUCCESS);
//::     elif field_match_type == MatchType.RANGE:
  get_f_${fnB}B(p4info, ${t.id_}, ${fid}, match_spec->${field_name}_start, ${nbytes}, &netv_1);
  get_f_${fnB}B(p4info, ${t.id_}, ${fid}, match_spec->${field_name}_end, ${nbytes}, &netv_1);
  rc = pi_match_key_range_set(mk, &netv_1, &netv_2);
  assert(rc == PI_STATUS_SUCCESS);
//::     else:
//::       assert(0)
//::     #endif

//::   #endfor
}

//:: #endfor
//::

//:: for a_name, a in actions.items():
//::   if not a.runtime_data: continue
//::   a_name = get_c_name(a_name)
//::   action_params = gen_action_params(a.runtime_data)
static void build_action_data_${a_name} (
    const pi_p4info_t *p4info, pi_action_data_t *adata, ${pd_prefix}${a_name}_action_spec_t *action_spec
) {
  pi_action_data_init(adata);
  pi_netv_t netv;
  pi_status_t rc;
//::   idx = 0
//::   for name, pid, width in action_params:
//::     name = get_c_name(name)
//::     fnB = width if width <= 4 else 'X'
  get_f_${fnB}B(p4info, ${a.id_}, ${pid}, action_spec->${name}, ${width}, &netv);
  rc = pi_action_data_arg_set(adata, &netv);
  assert(rc == PI_STATUS_SUCCESS);
//::     idx += 1
//::   #endfor
}

//:: #endfor

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
) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.device_id);
  pi_match_key_t *mk;
  pi_match_key_allocate(p4info, ${t.id_}, &mk);
//::     if has_match_spec:
  build_key_${t_name}(p4info, mk, match_spec);
//::     #endif
//::     if match_type in {MatchType.TERNARY, MatchType.RANGE}:
  pi_match_key_set_priority(mk, priority);
//::     #endif
  pi_action_data_t *adata;
  pi_action_data_allocate(p4info, ${a.id_}, &adata);
//::     if has_action_spec:
  build_action_data_${a_name}(p4info, adata, action_spec);
//::     #endif

  pi_entry_properties_t entry_properties;
  pi_entry_properties_clear(&entry_properties);

  pi_table_entry_t t_entry;
  t_entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  t_entry.entry.action_data = adata;
  t_entry.entry_properties = &entry_properties;
//::     if t.direct_meters:
  pi_direct_res_config_one_t meter_config;
  pi_direct_res_config_t configs;
  t_entry.direct_res_config = &configs;
  configs.num_configs = 1;
  configs.configs = &meter_config;
  meter_config.res_id = ${t.direct_meters.id_};
  pi_meter_spec_t pi_meter_spec;
  meter_config.config = (void *) &pi_meter_spec;
//::       if t.direct_meters.unit == MeterUnit.PACKETS:
  pd_to_pi_packets_meter_spec(${t.direct_meters.name}_spec, &pi_meter_spec);
//::       else:
  pd_to_pi_bytes_meter_spec(${t.direct_meters.name}_spec, &pi_meter_spec);
//::       #endif
//::     else:
  t_entry.direct_res_config = NULL;
//::     #endif

  pi_status_t rc;
  pi_entry_handle_t handle = 0;
  rc = pi_table_entry_add(sess_hdl, convert_dev_tgt(dev_tgt),
                          ${t.id_}, mk, &t_entry, 0, &handle);
  if (rc == PI_STATUS_SUCCESS) *entry_hdl = handle;
  pi_match_key_destroy(mk);
  pi_action_data_destroy(adata);
  return rc;
}

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
) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.device_id);
  pi_match_key_t *mk;
  pi_match_key_allocate(p4info, ${t.id_}, &mk);
//::     if has_match_spec:
  build_key_${t_name}(p4info, mk, match_spec);
//::     #endif
//::     if match_type in {MatchType.TERNARY, MatchType.RANGE}:
  pi_match_key_set_priority(mk, priority);
//::     #endif

  pi_entry_properties_t entry_properties;
  pi_entry_properties_clear(&entry_properties);

  pi_table_entry_t t_entry;
  t_entry.entry_type = PI_ACTION_ENTRY_TYPE_INDIRECT;
  t_entry.entry.indirect_handle = mbr_hdl;
  t_entry.entry_properties = &entry_properties;
  t_entry.direct_res_config = NULL;

  pi_status_t rc;
  pi_entry_handle_t handle = 0;
  rc = pi_table_entry_add(sess_hdl, convert_dev_tgt(dev_tgt),
                          ${t.id_}, mk, &t_entry, 0, &handle);
  if (rc == PI_STATUS_SUCCESS) *entry_hdl = handle;
  pi_match_key_destroy(mk);
  return rc;
}

//::   if t_type != TableType.INDIRECT_WS: continue
//::   params_indirect_ws = params + ["p4_pd_grp_hdl_t grp_hdl", "p4_pd_entry_hdl_t *entry_hdl"]
//::   param_str = ",\n ".join(params_indirect_ws)
//::   name = pd_prefix + t_name + "_add_entry_with_selector"
p4_pd_status_t
${name}
(
 ${param_str}
) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.device_id);
  pi_match_key_t *mk;
  pi_match_key_allocate(p4info, ${t.id_}, &mk);
//::     if has_match_spec:
  build_key_${t_name}(p4info, mk, match_spec);
//::     #endif
//::     if match_type in {MatchType.TERNARY, MatchType.RANGE}:
  pi_match_key_set_priority(mk, priority);
//::     #endif

  pi_entry_properties_t entry_properties;
  pi_entry_properties_clear(&entry_properties);

  pi_table_entry_t t_entry;
  t_entry.entry_type = PI_ACTION_ENTRY_TYPE_INDIRECT;
  t_entry.entry.indirect_handle = grp_hdl;
  t_entry.entry_properties = &entry_properties;
  t_entry.direct_res_config = NULL;

  pi_status_t rc;
  pi_entry_handle_t handle = 0;
  rc = pi_table_entry_add(sess_hdl, convert_dev_tgt(dev_tgt),
                          ${t.id_}, mk, &t_entry, 0, &handle);
  if (rc == PI_STATUS_SUCCESS) *entry_hdl = handle;
  pi_match_key_destroy(mk);
  return rc;
}

//:: #endfor

/* DELETE ENTRIES */

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   t_name = get_c_name(t_name)
//::   name = pd_prefix + t_name + "_table_delete"
p4_pd_status_t
${name}
(
 p4_pd_sess_hdl_t sess_hdl,
 uint8_t dev_id,
 p4_pd_entry_hdl_t entry_hdl
) {
  pi_status_t rc;
  rc = pi_table_entry_delete(sess_hdl, dev_id, ${t.id_}, entry_hdl);
  return rc;
}

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
) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_id);
  pi_action_data_t *adata;
  pi_action_data_allocate(p4info, ${a.id_}, &adata);
//::     if has_action_spec:
  build_action_data_${a_name}(p4info, adata, action_spec);
//::     #endif

  pi_table_entry_t t_entry;
  t_entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  t_entry.entry.action_data = adata;
  t_entry.entry_properties = NULL;
//::     if t.direct_meters:
  pi_direct_res_config_one_t meter_config;
  pi_direct_res_config_t configs;
  t_entry.direct_res_config = &configs;
  configs.num_configs = 1;
  configs.configs = &meter_config;
  meter_config.res_id = ${t.direct_meters.id_};
  pi_meter_spec_t pi_meter_spec;
  meter_config.config = (void *) &pi_meter_spec;
//::       if t.direct_meters.unit == MeterUnit.PACKETS:
  pd_to_pi_packets_meter_spec(${t.direct_meters.name}_spec, &pi_meter_spec);
//::       else:
  pd_to_pi_bytes_meter_spec(${t.direct_meters.name}_spec, &pi_meter_spec);
//::       #endif
//::     else:
  t_entry.direct_res_config = NULL;
//::     #endif

  pi_status_t rc;
  rc = pi_table_entry_modify(sess_hdl, dev_id, ${t.id_}, entry_hdl, &t_entry);
  pi_action_data_destroy(adata);
  return rc;
}

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
//::     params += get_direct_parameter_specs(t)
//::     params += ["p4_pd_entry_hdl_t *entry_hdl"]
//::     param_str = ",\n ".join(params)
//::     name = pd_prefix + t_name + "_set_default_action_" + a_name
p4_pd_status_t
${name}
(
 ${param_str}
) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.device_id);
  pi_action_data_t *adata;
  pi_action_data_allocate(p4info, ${a.id_}, &adata);
//::     if has_action_spec:
  build_action_data_${a_name}(p4info, adata, action_spec);
//::     #endif

  pi_table_entry_t t_entry;
  t_entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  t_entry.entry.action_data = adata;
  t_entry.entry_properties = NULL;
//::     if t.direct_meters:
  pi_direct_res_config_one_t meter_config;
  pi_direct_res_config_t configs;
  t_entry.direct_res_config = &configs;
  configs.num_configs = 1;
  configs.configs = &meter_config;
  meter_config.res_id = ${t.direct_meters.id_};
  pi_meter_spec_t pi_meter_spec;
  meter_config.config = (void *) &pi_meter_spec;
//::       if t.direct_meters.unit == MeterUnit.PACKETS:
  pd_to_pi_packets_meter_spec(${t.direct_meters.name}_spec, &pi_meter_spec);
//::       else:
  pd_to_pi_bytes_meter_spec(${t.direct_meters.name}_spec, &pi_meter_spec);
//::       #endif
//::     else:
  t_entry.direct_res_config = NULL;
//::     #endif

  pi_status_t rc;
  rc = pi_table_default_action_set(sess_hdl, convert_dev_tgt(dev_tgt),
                                   ${t.id_}, &t_entry);
  pi_action_data_destroy(adata);
  return rc;
}

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
) {
  // TODO(antonin)
  return 0;
}

//::   if t_type != TableType.INDIRECT_WS: continue
//::   params_indirect_ws = params + ["p4_pd_grp_hdl_t grp_hdl", "p4_pd_entry_hdl_t *entry_hdl"]
//::   param_str = ",\n ".join(params_indirect_ws)
//::   name = pd_prefix + t_name + "_set_default_entry_with_selector"
p4_pd_status_t
${name}
(
 ${param_str}
) {
  // TODO(antonin)
  return 0;
}

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
) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.device_id);
  pi_action_data_t *adata;
  pi_action_data_allocate(p4info, ${a.id_}, &adata);
//::     if has_action_spec:
  build_action_data_${a_name}(p4info, adata, action_spec);
//::     #endif
  pi_status_t rc;
  pi_indirect_handle_t handle;
  rc = pi_act_prof_mbr_create(sess_hdl, convert_dev_tgt(dev_tgt),
                              ${act_prof.id_}, adata, &handle);
  if (rc == PI_STATUS_SUCCESS) *mbr_hdl = handle;
  pi_action_data_destroy(adata);
  return rc;
}

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
) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_id);
  pi_action_data_t *adata;
  pi_action_data_allocate(p4info, ${a.id_}, &adata);
//::     if has_action_spec:
  build_action_data_${a_name}(p4info, adata, action_spec);
//::     #endif
  pi_status_t rc;
  rc = pi_act_prof_mbr_modify(sess_hdl, dev_id,
                              ${act_prof.id_}, mbr_hdl, adata);
  pi_action_data_destroy(adata);
  return rc;
}

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
) {
  return pi_act_prof_mbr_delete(sess_hdl, dev_id, ${act_prof.id_}, mbr_hdl);
}

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
) {
  pi_status_t rc;
  pi_indirect_handle_t handle;
  rc = pi_act_prof_grp_create(sess_hdl, convert_dev_tgt(dev_tgt),
                              ${act_prof.id_}, max_grp_size, &handle);
  if (rc == PI_STATUS_SUCCESS) *grp_hdl = handle;
  return rc;
}

//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "uint8_t dev_id",
//::             "p4_pd_grp_hdl_t grp_hdl"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + act_prof_name + "_del_group"
p4_pd_status_t
${name}
(
 ${param_str}
) {
  return pi_act_prof_grp_delete(sess_hdl, dev_id, ${act_prof.id_}, grp_hdl);
}

//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "uint8_t dev_id",
//::             "p4_pd_grp_hdl_t grp_hdl",
//::             "p4_pd_mbr_hdl_t mbr_hdl"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + act_prof_name + "_add_member_to_group"
p4_pd_status_t
${name}
(
 ${param_str}
) {
  return pi_act_prof_grp_add_mbr(sess_hdl, dev_id, ${act_prof.id_},
                                 grp_hdl, mbr_hdl);
}

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
) {
  return pi_act_prof_grp_remove_mbr(sess_hdl, dev_id, ${act_prof.id_},
                                    grp_hdl, mbr_hdl);
}

//:: #endfor

/* DIRECT COUNTERS */

/* legacy code, to be removed at some point */

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
) {
  // TODO(antonin)
  return 0;
}

//::   name = pd_prefix + t_name + "_reset_counters"
p4_pd_status_t
${name}
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt
) {
  // TODO(antonin)
  return 0;
}

//:: #endfor

//:: for t_name, t in tables.items():
//:: if not t.support_timeout: continue
//::   p4_pd_enable_hit_state_scan = "_".join([pd_prefix[:-1], t_name, "enable_hit_state_scan"])
//::   p4_pd_get_hit_state = "_".join([pd_prefix[:-1], t_name, "get_hit_state"])
//::   p4_pd_set_entry_ttl = "_".join([pd_prefix[:-1], t_name, "set_entry_ttl"])
//::   p4_pd_enable_entry_timeout = "_".join([pd_prefix[:-1], t_name, "enable_entry_timeout"])
p4_pd_status_t
${p4_pd_enable_hit_state_scan}(p4_pd_sess_hdl_t sess_hdl, uint32_t scan_interval) {
  // This function is a no-op. Needed for real hardware.
  (void)sess_hdl;
  (void)scan_interval;
  return 0;
}

p4_pd_status_t
${p4_pd_get_hit_state}(p4_pd_sess_hdl_t sess_hdl, p4_pd_entry_hdl_t entry_hdl, p4_pd_hit_state_t *hit_state) {
  (void) sess_hdl; (void) entry_hdl;
  *hit_state = ENTRY_HIT; /* TODO */
  return 0;
}

p4_pd_status_t
${p4_pd_set_entry_ttl}(p4_pd_sess_hdl_t sess_hdl, p4_pd_entry_hdl_t entry_hdl, uint32_t ttl) {
  (void) sess_hdl; (void) entry_hdl; (void) ttl;
  return 0;
}

p4_pd_status_t ${pd_prefix}ageing_set_cb(int dev_id, int table_id,
					 p4_pd_notify_timeout_cb cb_fn,
					 void *cb_cookie);

p4_pd_status_t
${p4_pd_enable_entry_timeout}(p4_pd_sess_hdl_t sess_hdl,
			      p4_pd_notify_timeout_cb cb_fn,
			      uint32_t max_ttl,
			      void *client_data) {
  (void) sess_hdl; (void) max_ttl;
  // TODO: use max_ttl to set up sweep interval
  return ${pd_prefix}ageing_set_cb(0, ${t.id_}, cb_fn, client_data);
}
//:: #endfor

/* Clean all state */
//:: name = pd_prefix + "clean_all"
p4_pd_status_t
${name}(p4_pd_sess_hdl_t sess_hdl, p4_pd_dev_target_t dev_tgt) {
  // TODO(antonin)
  return 0;
}
