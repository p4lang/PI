/* Copyright 2019-present Barefoot Networks, Inc.
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

#include "test_proto_fe_base.h"

namespace pi {
namespace proto {
namespace testing {

/* static */constexpr const char *DeviceMgrBaseTest::invalid_p4_id_error_str;

/* static */ pi_p4info_t *DeviceMgrUnittestBaseTest::p4info = nullptr;
/* static */ p4configv1::P4Info DeviceMgrUnittestBaseTest::p4info_proto;

}  // namespace testing
}  // namespace proto
}  // namespace pi
