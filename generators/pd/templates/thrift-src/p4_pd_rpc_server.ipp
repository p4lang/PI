//:: pd_prefix = "p4_pd_" + p4_prefix + "_"
//:: api_prefix = p4_prefix + "_"

#include "p4_prefix.h"

#include <iostream>

#include <string.h>

#include "pd/pd.h"

#include <list>
#include <map>
#include <mutex>
#include <thread>
#include <condition_variable>

using namespace  ::p4_pd_rpc;
using namespace  ::res_pd_rpc;

//:: def get_direct_parameter_specs(d, t, api_prefix):
//::   for k in d:
//::     exec "%s=d[k]" % k
//::   #endfor
//::   specs = []
//::   if t.direct_meters:
//::     m_name = t.direct_meters
//::     m = meter_arrays[m_name]
//::     if m.type_ == MeterType.PACKETS:
//::       specs += ["const " + api_prefix + "packets_meter_spec_t &" + m_name + "_spec"]
//::     else:
//::       specs += ["const " + api_prefix + "bytes_meter_spec_t &" + m_name + "_spec"]
//::     #endif
//::   #endif
//::   return specs
//:: #enddef

class ${p4_prefix}Handler : virtual public ${p4_prefix}If {
private:
  class CbWrap {
    CbWrap() {}

    int wait() {
      std::unique_lock<std::mutex> lock(cb_mutex);
      while(cb_status == 0) {
        cb_condvar.wait(lock);
      }
      return 0;
    }

    void notify() {
      std::unique_lock<std::mutex> lock(cb_mutex);
      assert(cb_status == 0);
      cb_status = 1;
      cb_condvar.notify_one();
    }

    static void cb_fn(int device_id, void *cookie) {
      (void) device_id;
      CbWrap *inst = static_cast<CbWrap *>(cookie);
      inst->notify();
    }

    CbWrap(const CbWrap &other) = delete;
    CbWrap &operator=(const CbWrap &other) = delete;

    CbWrap(CbWrap &&other) = delete;
    CbWrap &operator=(CbWrap &&other) = delete;

   private:
    std::mutex cb_mutex{};
    std::condition_variable cb_condvar{};
    int cb_status{0};
  };

public:
    ${p4_prefix}Handler() {
    }

    // Table entry add functions

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type != TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   match_type = t.match_type
//::   has_match_spec = len(t.key) > 0
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["const SessionHandle_t sess_hdl",
//::               "const DevTarget_t &dev_tgt"]
//::     if has_match_spec:
//::       params += ["const " + api_prefix + t_name + "_match_spec_t &match_spec"]
//::     #endif
//::     if match_type in {MatchType.TERNARY, MatchType.RANGE}:
//::       params += ["const int32_t priority"]
//::     #endif
//::     if has_action_spec:
//::       params += ["const " + api_prefix + a_name + "_action_spec_t &action_spec"]
//::     #endif
//::     if t.support_timeout:
//::       params += ["const int32_t ttl"]
//::     #endif
//::     params += get_direct_parameter_specs(render_dict, t, api_prefix)
//::     param_str = ", ".join(params)
//::     name = t_name + "_table_add_with_" + a_name
//::     pd_name = pd_prefix + name
    EntryHandle_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        p4_pd_dev_target_t pd_dev_tgt;
        pd_dev_tgt.device_id = dev_tgt.dev_id;
        pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;

//::     if has_match_spec:
        ${pd_prefix}${t_name}_match_spec_t pd_match_spec;
//::       match_params = gen_match_params(t.key)
//::       for name, width in match_params:
//::         name = get_c_name(name)
//::         if width <= 4:
        pd_match_spec.${name} = match_spec.${name};
//::         else:
	memcpy(pd_match_spec.${name}, match_spec.${name}.c_str(), ${width});
//::         #endif
//::       #endfor

//::     #endif
//::     if has_action_spec:
        ${pd_prefix}${a_name}_action_spec_t pd_action_spec;
//::       action_params = gen_action_params(a.runtime_data)
//::       for name, width in action_params:
//::         name = get_c_name(name)
//::         if width <= 4:
        pd_action_spec.${name} = action_spec.${name};
//::         else:
	memcpy(pd_action_spec.${name}, action_spec.${name}.c_str(), ${width});
//::         #endif
//::       #endfor

//::     #endif
        p4_pd_entry_hdl_t pd_entry;

//::     pd_params = ["sess_hdl", "pd_dev_tgt"]
//::     if has_match_spec:
//::       pd_params += ["&pd_match_spec"]
//::     #endif
//::     if match_type in {MatchType.TERNARY, MatchType.RANGE}:
//::       pd_params += ["priority"]
//::     #endif
//::     if has_action_spec:
//::       pd_params += ["&pd_action_spec"]
//::     #endif
//::     if t.support_timeout:
//::       pd_params += ["(uint32_t)ttl"]
//::     #endif
//::     # direct parameter specs
//::     if t.direct_meters:
//::       m_name = t.direct_meters
//::       m = meter_arrays[m_name]
//::       type_name = MeterType.to_str(m.type_)
        p4_pd_${type_name}_meter_spec_t pd_${m_name}_spec;
        ${type_name}_meter_spec_thrift_to_pd(${m_name}_spec, &pd_${m_name}_spec);
//::       pd_params += ["&pd_" + m_name + "_spec"]
//::     #endif
//::     pd_params += ["&pd_entry"]
//::     pd_param_str = ", ".join(pd_params)
        ${pd_name}(${pd_param_str});
        return pd_entry;
    }

//::   #endfor
//:: #endfor


    // Table entry modify functions

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type != TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["const SessionHandle_t sess_hdl",
//::               "const int8_t dev_id",
//::               "const EntryHandle_t entry"]
//::     if has_action_spec:
//::       params += ["const " + api_prefix + a_name + "_action_spec_t &action_spec"]
//::     #endif
//::     params += get_direct_parameter_specs(render_dict, t, api_prefix)
//::     param_str = ", ".join(params)
//::     name = t_name + "_table_modify_with_" + a_name
//::     pd_name = pd_prefix + name
    EntryHandle_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

//::     if has_action_spec:
        ${pd_prefix}${a_name}_action_spec_t pd_action_spec;
//::       action_params = gen_action_params(a.runtime_data)
//::       for name, width in action_params:
//::         name = get_c_name(name)
//::         if width <= 4:
        pd_action_spec.${name} = action_spec.${name};
//::         else:
	memcpy(pd_action_spec.${name}, action_spec.${name}.c_str(), ${width});
//::         #endif
//::       #endfor

//::     #endif

//::     pd_params = ["sess_hdl", "dev_id", "entry"]
//::     if has_action_spec:
//::       pd_params += ["&pd_action_spec"]
//::     #endif
//::     # direct parameter specs
//::     if t.direct_meters:
//::       m_name = t.direct_meters
//::       m = meter_arrays[m_name]
//::       type_name = MeterType.to_str(m.type_)
        p4_pd_${type_name}_meter_spec_t pd_${m_name}_spec;
        ${type_name}_meter_spec_thrift_to_pd(${m_name}_spec, &pd_${m_name}_spec);
//::       pd_params += ["&pd_" + m_name + "_spec"]
//::     #endif
//::     pd_param_str = ", ".join(pd_params)
        return ${pd_name}(${pd_param_str});
    }

//::   #endfor
//:: #endfor


    // Table entry delete functions

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   t_name = get_c_name(t_name)
//::   name = t_name + "_table_delete"
//::   pd_name = pd_prefix + name
//::   params = ["const SessionHandle_t sess_hdl",
//::             "const int8_t dev_id",
//::             "const EntryHandle_t entry"]
//::   param_str = ", ".join(params)
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        return ${pd_name}(sess_hdl, dev_id, entry);
    }

//:: #endfor

    // set default action

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type != TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["const SessionHandle_t sess_hdl",
//::               "const DevTarget_t &dev_tgt"]
//::     if has_action_spec:
//::       params += ["const " + api_prefix + a_name + "_action_spec_t &action_spec"]
//::     #endif
//::     params += get_direct_parameter_specs(render_dict, t, api_prefix)
//::     param_str = ", ".join(params)
//::     name = t_name + "_set_default_action_" + a_name
//::     pd_name = pd_prefix + name
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        p4_pd_dev_target_t pd_dev_tgt;
        pd_dev_tgt.device_id = dev_tgt.dev_id;
        pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;

//::     if has_action_spec:
        ${pd_prefix}${a_name}_action_spec_t pd_action_spec;
//::       action_params = gen_action_params(a.runtime_data)
//::       for name, width in action_params:
//::         name = get_c_name(name)
//::         if width <= 4:
        pd_action_spec.${name} = action_spec.${name};
//::         else:
	memcpy(pd_action_spec.${name}, action_spec.${name}.c_str(), ${width});
//::         #endif
//::       #endfor

//::     #endif
        p4_pd_entry_hdl_t pd_entry;

//::     pd_params = ["sess_hdl", "pd_dev_tgt"]
//::     if has_action_spec:
//::       pd_params += ["&pd_action_spec"]
//::     #endif
//::     # direct parameter specs
//::     if t.direct_meters:
//::       m_name = t.direct_meters
//::       m = meter_arrays[m_name]
//::       type_name = MeterType.to_str(m.type_)
        p4_pd_${type_name}_meter_spec_t pd_${m_name}_spec;
        ${type_name}_meter_spec_thrift_to_pd(${m_name}_spec, &pd_${m_name}_spec);
//::       pd_params += ["&pd_" + m_name + "_spec"]
//::     #endif
//::     pd_params += ["&pd_entry"]
//::     pd_param_str = ", ".join(pd_params)
        return ${pd_name}(${pd_param_str});

        // return pd_entry;
    }

//::   #endfor
//:: #endfor

//:: name = "clean_all"
//:: pd_name = pd_prefix + name
  int32_t ${name}(const SessionHandle_t sess_hdl, const DevTarget_t &dev_tgt) {
      std::cerr << "In ${name}\n";

      p4_pd_dev_target_t pd_dev_tgt;
      pd_dev_tgt.device_id = dev_tgt.dev_id;
      pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;

      return ${pd_name}(sess_hdl, pd_dev_tgt);
  }

    // INDIRECT ACTION DATA AND MATCH SELECT

//:: for act_prof_name, act_prof in act_profs.items():
//::   act_prof_name = get_c_name(act_prof_name)
//::   for a_name, a in t.actions.items():
//::     a_name = get_c_name(a_name)
//::     has_action_spec = len(a.runtime_data) > 0
//::     params = ["const SessionHandle_t sess_hdl",
//::               "const DevTarget_t &dev_tgt"]
//::     if has_action_spec:
//::       params += ["const " + api_prefix + a_name + "_action_spec_t &action_spec"]
//::     #endif
//::     param_str = ", ".join(params)
//::     name = act_prof_name + "_add_member_with_" + a_name
//::     pd_name = pd_prefix + name
    EntryHandle_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        p4_pd_dev_target_t pd_dev_tgt;
        pd_dev_tgt.device_id = dev_tgt.dev_id;
        pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;

//::     if has_action_spec:
        ${pd_prefix}${a_name}_action_spec_t pd_action_spec;
//::       action_params = gen_action_params(a.runtime_data)
//::       for name, width in action_params:
//::         name = get_c_name(name)
//::         if width <= 4:
        pd_action_spec.${name} = action_spec.${name};
//::         else:
	memcpy(pd_action_spec.${name}, action_spec.${name}.c_str(), ${width});
//::         #endif
//::       #endfor

//::     #endif
        p4_pd_mbr_hdl_t pd_mbr_hdl;

//::     pd_params = ["sess_hdl", "pd_dev_tgt"]
//::     if has_action_spec:
//::       pd_params += ["&pd_action_spec"]
//::     #endif
//::     pd_params += ["&pd_mbr_hdl"]
//::     pd_param_str = ", ".join(pd_params)
        ${pd_name}(${pd_param_str});
        return pd_mbr_hdl;
    }

//::     params = ["const SessionHandle_t sess_hdl",
//::               "const int8_t dev_id",
//::               "const MemberHandle_t mbr"]
//::     if has_action_spec:
//::       params += ["const " + api_prefix + a_name + "_action_spec_t &action_spec"]
//::     #endif
//::     param_str = ", ".join(params)
//::     name = act_prof_name + "_modify_member_with_" + a_name
//::     pd_name = pd_prefix + name
    EntryHandle_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

//::     if has_action_spec:
        ${pd_prefix}${a_name}_action_spec_t pd_action_spec;
//::       action_params = gen_action_params(a.runtime_data)
//::       for name, width in action_params:
//::         name = get_c_name(name)
//::         if width <= 4:
        pd_action_spec.${name} = action_spec.${name};
//::         else:
	memcpy(pd_action_spec.${name}, action_spec.${name}.c_str(), ${width});
//::         #endif
//::       #endfor

//::     #endif

//::     pd_params = ["sess_hdl", "dev_id", "mbr"]
//::     if has_action_spec:
//::       pd_params += ["&pd_action_spec"]
//::     #endif
//::     pd_param_str = ", ".join(pd_params)
        return ${pd_name}(${pd_param_str});
    }

//::   #endfor

//::   params = ["const SessionHandle_t sess_hdl",
//::             "const int8_t dev_id",
//::             "const MemberHandle_t mbr"]
//::   param_str = ", ".join(params)
//::   name = act_prof_name + "_del_member"
//::   pd_name = pd_prefix + name
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        return ${pd_name}(sess_hdl, dev_id, mbr);
    }

//::   if not act_prof.with_selector: continue
//::
//::   params = ["const SessionHandle_t sess_hdl",
//::             "const DevTarget_t &dev_tgt",
//::             "const int16_t max_grp_size"]
//::   param_str = ", ".join(params)
//::   name = act_prof_name + "_create_group"
//::   pd_name = pd_prefix + name
    GroupHandle_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        p4_pd_dev_target_t pd_dev_tgt;
        pd_dev_tgt.device_id = dev_tgt.dev_id;
        pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;

	p4_pd_grp_hdl_t pd_grp_hdl;

        ${pd_name}(sess_hdl, pd_dev_tgt, max_grp_size, &pd_grp_hdl);
	return pd_grp_hdl;
    }

//::   params = ["const SessionHandle_t sess_hdl",
//::             "const int8_t dev_id",
//::             "const GroupHandle_t grp"]
//::   param_str = ", ".join(params)
//::   name = act_prof_name + "_del_group"
//::   pd_name = pd_prefix + name
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        return ${pd_name}(sess_hdl, dev_id, grp);
    }

//::   params = ["const SessionHandle_t sess_hdl",
//::             "const int8_t dev_id",
//::             "const GroupHandle_t grp",
//::             "const MemberHandle_t mbr"]
//::   param_str = ", ".join(params)
//::   name = act_prof_name + "_add_member_to_group"
//::   pd_name = pd_prefix + name
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        return ${pd_name}(sess_hdl, dev_id, grp, mbr);
    }

//::   params = ["const SessionHandle_t sess_hdl",
//::             "const int8_t dev_id",
//::             "const GroupHandle_t grp",
//::             "const MemberHandle_t mbr"]
//::   param_str = ", ".join(params)
//::   name = act_prof_name + "_del_member_from_group"
//::   pd_name = pd_prefix + name
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        return ${pd_name}(sess_hdl, dev_id, grp, mbr);
    }

//::   params = ["const SessionHandle_t sess_hdl",
//::             "const int8_t dev_id",
//::             "const GroupHandle_t grp",
//::             "const MemberHandle_t mbr"]
//::   param_str = ", ".join(params)
//::   name = act_prof_name + "_deactivate_group_member"
//::   pd_name = pd_prefix + name
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        return 0;
    }

//::   params = ["const SessionHandle_t sess_hdl",
//::             "const int8_t dev_id",
//::             "const GroupHandle_t grp",
//::             "const MemberHandle_t mbr"]
//::   param_str = ", ".join(params)
//::   name = act_prof_name + "_reactivate_group_member"
//::   pd_name = pd_prefix + name
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        return 0;
    }

//:: #endfor

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type == TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   match_type = t.match_type
//::   has_match_spec = len(t.key) > 0
//::   params = ["const SessionHandle_t sess_hdl",
//::             "const DevTarget_t &dev_tgt"]
//::   if has_match_spec:
//::     params += ["const " + api_prefix + t_name + "_match_spec_t &match_spec"]
//::   #endif
//::   if match_type in {MatchType.TERNARY, MatchType.RANGE}:
//::     params += ["const int32_t priority"]
//::   #endif
//::   params_wo = params + ["const MemberHandle_t mbr"]
//::   param_str = ", ".join(params_wo)
//::   name = t_name + "_add_entry"
//::   pd_name = pd_prefix + name
    EntryHandle_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        p4_pd_dev_target_t pd_dev_tgt;
        pd_dev_tgt.device_id = dev_tgt.dev_id;
        pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;

//::   if has_match_spec:
        ${pd_prefix}${t_name}_match_spec_t pd_match_spec;
//::     match_params = gen_match_params(t.key)
//::     for name, width in match_params:
//::       name = get_c_name(name)
//::       if width <= 4:
        pd_match_spec.${name} = match_spec.${name};
//::       else:
	memcpy(pd_match_spec.${name}, match_spec.${name}.c_str(), ${width});
//::       #endif
//::     #endfor

//::   #endif
        p4_pd_entry_hdl_t pd_entry;

//::   pd_params = ["sess_hdl", "pd_dev_tgt"]
//::   if has_match_spec:
//::     pd_params += ["&pd_match_spec"]
//::   #endif
//::   if match_type in {MatchType.TERNARY, MatchType.RANGE}:
//::     pd_params += ["priority"]
//::   #endif
//::   pd_params += ["mbr", "&pd_entry"]
//::   pd_param_str = ", ".join(pd_params)
        ${pd_name}(${pd_param_str});
        return pd_entry;
    }

//::   if t_type != TableType.INDIRECT_WS: continue
//::   params_w = params + ["const GroupHandle_t grp"]
//::   param_str = ", ".join(params_w)
//::   name = t_name + "_add_entry_with_selector"
//::   pd_name = pd_prefix + name
    EntryHandle_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        p4_pd_dev_target_t pd_dev_tgt;
        pd_dev_tgt.device_id = dev_tgt.dev_id;
        pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;

//::   if has_match_spec:
        ${pd_prefix}${t_name}_match_spec_t pd_match_spec;
//::     match_params = gen_match_params(t.key)
//::     for name, width in match_params:
//::       name = get_c_name(name)
//::       if width <= 4:
        pd_match_spec.${name} = match_spec.${name};
//::       else:
	memcpy(pd_match_spec.${name}, match_spec.${name}.c_str(), ${width});
//::       #endif
//::     #endfor

//::   #endif
        p4_pd_entry_hdl_t pd_entry;

//::   pd_params = ["sess_hdl", "pd_dev_tgt"]
//::   if has_match_spec:
//::     pd_params += ["&pd_match_spec"]
//::   #endif
//::   if match_type in {MatchType.TERNARY, MatchType.RANGE}:
//::     pd_params += ["priority"]
//::   #endif
//::   pd_params += ["grp", "&pd_entry"]
//::   pd_param_str = ", ".join(pd_params)
        ${pd_name}(${pd_param_str});
        return pd_entry;
    }

//:: #endfor

//:: for t_name, t in tables.items():
//::   t_type = t.type_
//::   if t_type == TableType.SIMPLE: continue
//::   t_name = get_c_name(t_name)
//::   params = ["const SessionHandle_t sess_hdl",
//::             "const DevTarget_t &dev_tgt"]
//::   params_wo = params + ["const MemberHandle_t mbr"]
//::   param_str = ", ".join(params_wo)
//::   name = t_name + "_set_default_entry"
//::   pd_name = pd_prefix + name
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        p4_pd_dev_target_t pd_dev_tgt;
        pd_dev_tgt.device_id = dev_tgt.dev_id;
        pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;

        p4_pd_entry_hdl_t pd_entry;

//::   pd_params = ["sess_hdl", "pd_dev_tgt"]
//::   pd_params += ["mbr", "&pd_entry"]
//::   pd_param_str = ", ".join(pd_params)
        ${pd_name}(${pd_param_str});

        return pd_entry;
    }

//::   if t_type != TableType.INDIRECT_WS: continue
//::   params_w = params + ["const GroupHandle_t grp"]
//::   param_str = ", ".join(params_w)
//::   name = t_name + "_set_default_entry_with_selector"
//::   pd_name = pd_prefix + name
    int32_t ${name}(${param_str}) {
        std::cerr << "In ${name}\n";

        p4_pd_dev_target_t pd_dev_tgt;
        pd_dev_tgt.device_id = dev_tgt.dev_id;
        pd_dev_tgt.dev_pipe_id = dev_tgt.dev_pipe_id;

        p4_pd_entry_hdl_t pd_entry;

//::   pd_params = ["sess_hdl", "pd_dev_tgt"]
//::   pd_params += ["grp", "&pd_entry"]
//::   pd_param_str = ", ".join(pd_params)
        ${pd_name}(${pd_param_str});

        return pd_entry;
    }
//:: #endfor
};
