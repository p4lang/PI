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

#include "pd_utils.h"

void pd_to_pi_bytes_meter_spec(const p4_pd_bytes_meter_spec_t *meter_spec,
                               pi_meter_spec_t *pi_meter_spec) {
  pi_meter_spec->meter_unit = PI_METER_UNIT_BYTES;

  // kbits per sec to bytes per sec
  pi_meter_spec->cir = meter_spec->cir_kbps * 1000 / 8;
  // kbits to bytes
  pi_meter_spec->cburst = meter_spec->cburst_kbits * 1000 / 8;

  pi_meter_spec->pir = meter_spec->pir_kbps * 1000 / 8;
  pi_meter_spec->pburst = meter_spec->pburst_kbits * 1000 / 8;

  switch (meter_spec->meter_type) {
    case PD_METER_TYPE_COLOR_AWARE:
      pi_meter_spec->meter_type = PI_METER_TYPE_COLOR_AWARE;
      break;
    case PD_METER_TYPE_COLOR_UNAWARE:
      pi_meter_spec->meter_type = PI_METER_TYPE_COLOR_UNAWARE;
      break;
  }
}

void pd_to_pi_packets_meter_spec(const p4_pd_packets_meter_spec_t *meter_spec,
                                 pi_meter_spec_t *pi_meter_spec) {
  pi_meter_spec->meter_unit = PI_METER_UNIT_PACKETS;

  pi_meter_spec->cir = meter_spec->cir_pps;
  pi_meter_spec->cburst = meter_spec->cburst_pkts;

  pi_meter_spec->pir = meter_spec->pir_pps;
  pi_meter_spec->pburst = meter_spec->pburst_pkts;

  switch (meter_spec->meter_type) {
    case PD_METER_TYPE_COLOR_AWARE:
      pi_meter_spec->meter_type = PI_METER_TYPE_COLOR_AWARE;
      break;
    case PD_METER_TYPE_COLOR_UNAWARE:
      pi_meter_spec->meter_type = PI_METER_TYPE_COLOR_UNAWARE;
      break;
  }
}
