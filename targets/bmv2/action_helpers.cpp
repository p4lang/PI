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

#include "action_helpers.h"

#include <PI/p4info.h>
#include <PI/int/pi_int.h>

#include <vector>
#include <string>

namespace pibmv2 {

std::vector<std::string> build_action_data(const pi_action_data_t *action_data,
                                           const pi_p4info_t *p4info) {
  std::vector<std::string> data;

  pi_p4_id_t action_id = action_data->action_id;
  assert(action_data);
  const char *ad_data = action_data->data;
  assert(ad_data);

  size_t num_params;
  const pi_p4_id_t *param_ids = pi_p4info_action_get_params(p4info, action_id,
                                                            &num_params);
  for (size_t i = 0; i < num_params; i++) {
    pi_p4_id_t p_id = param_ids[i];
    size_t p_bw = pi_p4info_action_param_bitwidth(p4info, p_id);
    size_t nbytes = (p_bw + 7) / 8;
    data.push_back(std::string(ad_data, nbytes));
    ad_data += nbytes;
  }

  return data;
}

}  // namespace pibmv2
