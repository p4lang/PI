/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef _P4_PD_COUNTERS_H_
#define _P4_PD_COUNTERS_H_

#include ${target_common_h}

#ifdef __cplusplus
extern "C" {
#endif

//:: for ca_name, ca in counter_arrays.items():
//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "p4_pd_dev_target_t dev_tgt"]
//::   if ca.is_direct:
//::     params += ["p4_pd_entry_hdl_t entry_hdl"]
//::   else:
//::     params += ["int index"]
//::   #endif
//::   params += ["int flags"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + "counter_read_" + ca_name
p4_pd_counter_value_t
${name}
(
 ${param_str}
);

//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "p4_pd_dev_target_t dev_tgt"]
//::   if ca.is_direct:
//::     params += ["p4_pd_entry_hdl_t entry_hdl"]
//::   else:
//::     params += ["int index"]
//::   #endif
//::   params += ["p4_pd_counter_value_t counter_value"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + "counter_write_" + ca_name
p4_pd_status_t
${name}
(
 ${param_str}
);

//::   name = pd_prefix + "counter_hw_sync_" + ca_name
p4_pd_status_t
${name}
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
);

//:: #endfor

#ifdef __cplusplus
}
#endif

#endif
