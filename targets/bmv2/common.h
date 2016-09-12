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

#ifndef PI_BMV2_COMMON_H_
#define PI_BMV2_COMMON_H_

#include <PI/pi.h>

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

}  // namespace pibmv2

#endif  // PI_BMV2_COMMON_H_
