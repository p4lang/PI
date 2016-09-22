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

#include "pd/pd_meters.h"
#include "pd_utils.h"

#include <PI/pi.h>
#include <PI/pi_meter.h>

__attribute__ ((unused))
static void pi_to_pd_bytes_meter_spec(
    const pi_meter_spec_t *pi_meter_spec,
    p4_pd_bytes_meter_spec_t *meter_spec) {
  // bytes per sec tp kbits per sec
  meter_spec->cir_kbps = pi_meter_spec->cir * 8 / 1000;
  // bytes to kbits
  meter_spec->cburst_kbits = pi_meter_spec->cburst * 8 / 1000;

  meter_spec->pir_kbps = pi_meter_spec->pir * 8 / 1000;
  meter_spec->pburst_kbits = pi_meter_spec->pburst * 8 / 1000;

  switch (pi_meter_spec->meter_type) {
    case PI_METER_UNIT_DEFAULT:
      assert(0);
      break;
    case PI_METER_TYPE_COLOR_AWARE:
      meter_spec->meter_type = PD_METER_TYPE_COLOR_AWARE;
      break;
    case PI_METER_TYPE_COLOR_UNAWARE:
      meter_spec->meter_type = PD_METER_TYPE_COLOR_UNAWARE;
      break;
  }
}

__attribute__ ((unused))
static void pi_to_pd_packets_meter_spec(
    const pi_meter_spec_t *pi_meter_spec,
    p4_pd_packets_meter_spec_t *meter_spec) {
  meter_spec->cir_pps = pi_meter_spec->cir;
  meter_spec->cburst_pkts = pi_meter_spec->cburst;

  meter_spec->pir_pps = pi_meter_spec->pir;
  meter_spec->pburst_pkts = pi_meter_spec->pburst;

  switch (pi_meter_spec->meter_type) {
    case PI_METER_UNIT_DEFAULT:
      assert(0);
      break;
    case PI_METER_TYPE_COLOR_AWARE:
      meter_spec->meter_type = PD_METER_TYPE_COLOR_AWARE;
      break;
    case PI_METER_TYPE_COLOR_UNAWARE:
      meter_spec->meter_type = PD_METER_TYPE_COLOR_UNAWARE;
      break;
  }
}

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
) {
  pi_status_t rc;
  pi_meter_spec_t pi_meter_spec;
//::   if ma.unit == MeterUnit.PACKETS:
  pd_to_pi_packets_meter_spec(meter_spec, &pi_meter_spec);
//::   else:
  pd_to_pi_bytes_meter_spec(meter_spec, &pi_meter_spec);
//::   #endif

//::   if ma.is_direct:
  rc = pi_meter_set_direct(sess_hdl, convert_dev_tgt(dev_tgt), ${ma.id_},
                           entry_hdl, &pi_meter_spec);
//::   else:
  rc = pi_meter_set(sess_hdl, convert_dev_tgt(dev_tgt), ${ma.id_}, index,
                    &pi_meter_spec);
//::   #endif

  return rc;
}

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
) {
  pi_status_t rc;
  pi_meter_spec_t pi_meter_spec;

//::   if ma.is_direct:
  rc = pi_meter_read_direct(sess_hdl, convert_dev_tgt(dev_tgt), ${ma.id_},
                            entry_hdl, &pi_meter_spec);
//::   else:
  rc = pi_meter_read(sess_hdl, convert_dev_tgt(dev_tgt), ${ma.id_}, index,
                     &pi_meter_spec);
//::   #endif

  if (rc != PI_STATUS_SUCCESS) return rc;

//::   if ma.unit == MeterUnit.PACKETS:
  pi_to_pd_packets_meter_spec(&pi_meter_spec, meter_spec);
//::   else:
  pi_to_pd_bytes_meter_spec(&pi_meter_spec, meter_spec);
//::   #endif

  return 0;
}

//:: #endfor
