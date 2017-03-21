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

#ifndef PI_PROTO_UTIL_H_
#define PI_PROTO_UTIL_H_

#include <cstdint>

namespace pi {

namespace proto {

namespace util {

using p4_id_t = uint32_t;

// we use the same integral value as the PI internally, but this is not a
// requirement
enum class P4ResourceType {
  INVALID = 0x00,

  ACTION = 0x01,
  TABLE = 0x02,
  ACTION_PROFILE = 0x11,
  COUNTER = 0x12,
  METER = 0x13,

  INVALID_MAX = 0x100,
};

constexpr p4_id_t invalid_id() { return 0; }

P4ResourceType resource_type_from_id(p4_id_t p4_id);

}  // namespace util

}  // namespace proto

}  // namespace pi

#endif  // PI_PROTO_UTIL_H_
