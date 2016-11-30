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

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

#include <PI/pi.h>

namespace pi {

namespace fe {

namespace proto {

namespace common {

struct SessionTemp {
  SessionTemp() { pi_session_init(&sess); }

  ~SessionTemp() { pi_session_cleanup(sess); }

  pi_session_handle_t get() const { return sess; }

  pi_session_handle_t sess;
};

}  // namespace common

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_COMMON_H_
