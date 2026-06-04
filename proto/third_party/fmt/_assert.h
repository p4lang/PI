/*
 * SPDX-FileCopyrightText: 2013 Barefoot Networks, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#ifndef FMT__ASSERT_H_
#define FMT__ASSERT_H_

// An assert that cannot be removed with NDEBUG

namespace fmt {

[[ noreturn ]] void _assert(const char* expr, const char* file, int line);

}  // namespace fmt

#define _FMT_ASSERT(expr) \
  ((expr) ? (void)0 : fmt::_assert(#expr, __FILE__, __LINE__))

#define _FMT_UNREACHABLE(msg) fmt::_assert(msg, __FILE__, __LINE__)

#define _FMT_UNUSED(x) ((void)x)

#endif  // FMT__ASSERT_H_
