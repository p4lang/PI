# SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//:__subpackages__"],
)

cc_library(
    name = "pitoolkit",
    srcs = glob(["*.c"]),
    hdrs = glob(["*.h"]),
    includes = ["."],
)
