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

#ifndef _P4_PD_UTILS_H_
#define _P4_PD_UTILS_H_

#include ${target_common_h}

#include <PI/pi.h>
#include <PI/pi_meter.h>

static inline pi_dev_tgt_t convert_dev_tgt(p4_pd_dev_target_t pd_dev_tgt) {
  pi_dev_tgt_t pi_dev_tgt;
  pi_dev_tgt.dev_id = pd_dev_tgt.device_id;
  pi_dev_tgt.dev_pipe_mask = pd_dev_tgt.dev_pipe_id;
  return pi_dev_tgt;
}

void pd_to_pi_bytes_meter_spec(const p4_pd_bytes_meter_spec_t *meter_spec,
                               pi_meter_spec_t *pi_meter_spec);

void pd_to_pi_packets_meter_spec(const p4_pd_packets_meter_spec_t *meter_spec,
                                 pi_meter_spec_t *pi_meter_spec);

#endif
