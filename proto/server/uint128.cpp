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

#include "uint128.h"

#include <iomanip>
#include <ostream>

namespace {

// Saves the internal state of a stream and restores it in the destructor
struct StreamStateSaver final {
  explicit StreamStateSaver(std::ios &s)  // NOLINT(runtime/references)
      : ref(s) {
    state.copyfmt(s);
  }

  ~StreamStateSaver() {
    ref.copyfmt(state);
  }

  std::ios &ref;
  std::ios state{nullptr};
};

}  // namespace

std::ostream &operator<<(std::ostream &out, const Uint128 &n) {
  StreamStateSaver state_saver(out);
  out << "0x";
  if (n.high_ == 0)
    out << std::hex << n.low_;
  else
    out << std::hex << n.high_ << std::setw(16) << std::setfill('0') << n.low_;
  return out;
}
