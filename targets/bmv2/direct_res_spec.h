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

#ifndef PI_BMV2_DIRECT_RES_SPEC_H_
#define PI_BMV2_DIRECT_RES_SPEC_H_

#include <PI/pi.h>

#include <vector>

#include "conn_mgr.h"

namespace pibmv2 {

BmCounterValue convert_from_counter_data(const pi_counter_data_t *from);

std::vector<BmMeterRateConfig> convert_from_meter_spec(
    const pi_meter_spec_t *meter_spec);

}  // namespace pibmv2

#endif  // PI_BMV2_DIRECT_RES_SPEC_H_
