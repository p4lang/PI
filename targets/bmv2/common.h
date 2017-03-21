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

#ifndef PI_BMV2_COMMON_H_
#define PI_BMV2_COMMON_H_

#include <PI/int/pi_int.h>
#include <PI/p4info.h>
#include <PI/pi.h>

#include <string>
#include <unordered_map>

namespace pibmv2 {

typedef struct {
  int assigned;
  const pi_p4info_t *p4info;
} device_info_t;

extern device_info_t device_info_state[];

static inline device_info_t *get_device_info(size_t dev_id) {
  return &device_info_state[dev_id];
}

struct IndirectHMgr {
  static pi_indirect_handle_t make_grp_h(pi_indirect_handle_t h) {
    return h | grp_prefix;
  }

  static bool is_grp_h(pi_indirect_handle_t h) { return h & grp_prefix; }

  static pi_indirect_handle_t clear_grp_h(pi_indirect_handle_t h) {
    return h & (~grp_prefix);
  }

  static constexpr pi_indirect_handle_t grp_prefix =
      (1ull << (sizeof(pi_indirect_handle_t) * 8 - 1));
};

struct ADataSize {
  ADataSize(pi_p4_id_t id, size_t s)
      : id(id), s(s) { }
  pi_p4_id_t id;
  size_t s;

  static std::unordered_map<std::string, ADataSize> compute_action_sizes(
      const pi_p4info_t *p4info, const pi_p4_id_t *action_ids,
      size_t num_actions) {
    std::unordered_map<std::string, ADataSize> action_map;
    action_map.reserve(num_actions);

    for (size_t i = 0; i < num_actions; i++) {
      action_map.emplace(
          std::string(pi_p4info_action_name_from_id(p4info, action_ids[i])),
          ADataSize(action_ids[i],
                    pi_p4info_action_data_size(p4info, action_ids[i])));
    }

    return action_map;
  }
};

}  // namespace pibmv2

#endif  // PI_BMV2_COMMON_H_
