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

#ifndef _P4_PD_METERS_H_
#define _P4_PD_METERS_H_

#include ${target_common_h}

#ifdef __cplusplus
extern "C" {
#endif

//:: for ma_name, ma in meter_arrays.items():
//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "p4_pd_dev_target_t dev_tgt"]
//::   if ma.is_direct:
//::     params += ["p4_pd_entry_hdl_t entry_hdl"]
//::   else:
//::     params += ["int index"]
//::   #endif
//::   if ma.unit == MeterUnit.PACKETS:
//::     params += ["p4_pd_packets_meter_spec_t *meter_spec"]
//::   else:
//::     params += ["p4_pd_bytes_meter_spec_t *meter_spec"]
//::   #endif
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + "meter_set_" + ma_name
p4_pd_status_t
${name}
(
${param_str}
);

//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "p4_pd_dev_target_t dev_tgt"]
//::   if ma.is_direct:
//::     params += ["p4_pd_entry_hdl_t entry_hdl"]
//::   else:
//::     params += ["int index"]
//::   #endif
//::   if ma.unit == MeterUnit.PACKETS:
//::     params += ["p4_pd_packets_meter_spec_t *meter_spec"]
//::   else:
//::     params += ["p4_pd_bytes_meter_spec_t *meter_spec"]
//::   #endif
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + "meter_read_" + ma_name
p4_pd_status_t
${name}
(
${param_str}
);

//:: #endfor

#ifdef __cplusplus
}
#endif

#endif
