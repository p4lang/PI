// SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
//
// SPDX-License-Identifier: Apache-2.0

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "_assert.h"

#include <cstdlib>
#include <iostream>

namespace fmt {

void _assert(const char* expr, const char* file, int line) {
  std::cerr << "Assertion '" << expr << "' failed, file '" << file
            << "' line '" << line << "'.\n";
  std::abort();
}

}  // namespace fmt
