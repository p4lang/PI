/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
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

#include "action_helpers.h"

#include <PI/int/pi_int.h>
#include <PI/p4info.h>

#include <bm/Standard.h>

#include <string>
#include <vector>

#include <cstring>

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
    size_t p_bw = pi_p4info_action_param_bitwidth(p4info, action_id, p_id);
    size_t nbytes = (p_bw + 7) / 8;
    data.push_back(std::string(ad_data, nbytes));
    ad_data += nbytes;
  }

  return data;
}

char *dump_action_data(const pi_p4info_t *p4info, char *data,
                       pi_p4_id_t action_id,
                       const ::bm_runtime::standard::BmActionData &params) {
  // unfortunately, I have observed that bmv2 sometimes returns shorter binary
  // strings than it received (0 padding is removed), which makes things more
  // complicated and expensive here.
  size_t num_params;
  const pi_p4_id_t *param_ids = pi_p4info_action_get_params(
      p4info, action_id, &num_params);
  assert(num_params == params.size());
  for (size_t i = 0; i < num_params; i++) {
    size_t bitwidth = pi_p4info_action_param_bitwidth(p4info, action_id,
                                                      param_ids[i]);
    size_t nbytes = (bitwidth + 7) / 8;
    const auto &p = params.at(i);
    assert(nbytes >= p.size());
    size_t diff = nbytes - p.size();
    std::memset(data, 0, diff);
    std::memcpy(data + diff, p.data(), p.size());
    data += nbytes;
  }
  return data;
}

}  // namespace pibmv2
