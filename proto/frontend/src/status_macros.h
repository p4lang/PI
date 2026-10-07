// Protocol Buffers - Google's data interchange format
// Copyright 2008 Google Inc.  All rights reserved.
// https://developers.google.com/protocol-buffers/
// SPDX-FileCopyrightText: 2008 Google Inc.
//
// SPDX-License-Identifier: BSD-3-Clause

// Adpated from:
// https://github.com/protocolbuffers/protobuf/blob/master/src/google/protobuf/stubs/status_macros.h

#ifndef SRC_STATUS_MACROS_H_
#define SRC_STATUS_MACROS_H_

#include "google/rpc/status.pb.h"

#include "statusor.h"

namespace pi {

namespace fe {

namespace proto {

// Internal helper for concatenating macro values.
#define STATUS_MACROS_CONCAT_NAME_INNER(x, y) x##y
#define STATUS_MACROS_CONCAT_NAME(x, y) STATUS_MACROS_CONCAT_NAME_INNER(x, y)

#define ASSIGN_OR_RETURN_IMPL(statusor, lhs, rexpr)       \
  auto statusor = (rexpr);                              \
  if (!statusor.ok()) { return statusor.status(); }     \
  lhs = statusor.ValueOrDie();

// Executes an expression that returns a StatusOr, extracting its value into the
// variable defined by lhs (or returning on error).
//
// Example: Assigning to an existing value
//   ValueType value;
//   ASSIGN_OR_RETURN(value, MaybeGetValue(arg));
//
// WARNING: ASSIGN_OR_RETURN expands into multiple statements; it cannot be used
//  in a single statement (e.g. as the body of an if statement without {})!
#define ASSIGN_OR_RETURN(lhs, rexpr) \
  ASSIGN_OR_RETURN_IMPL( \
      STATUS_MACROS_CONCAT_NAME(_status_or_value, __COUNTER__), lhs, rexpr);

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_STATUS_MACROS_H_
