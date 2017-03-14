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

#include <PI/pi_base.h>

#include <PI/proto/util.h>

namespace pi {

namespace proto {

namespace util {

P4ResourceType
resource_type_from_id(p4_id_t p4_id) {
  switch (p4_id >> 24) {
    case PI_ACTION_ID:
      return P4ResourceType::ACTION;
    case PI_TABLE_ID:
      return P4ResourceType::TABLE;
    case PI_ACT_PROF_ID:
      return P4ResourceType::ACTION_PROFILE;
    case PI_COUNTER_ID:
      return P4ResourceType::COUNTER;
    case PI_METER_ID:
      return P4ResourceType::METER;
    default:
      return P4ResourceType::INVALID;
  }
}

}  // namespace util

}  // namespace proto

}  // namespace pi
