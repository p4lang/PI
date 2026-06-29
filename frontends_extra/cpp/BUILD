# SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "pifecpp",
    srcs = ["src/tables.cpp"],
    hdrs = ["PI/frontends/cpp/tables.h"],
    includes = ["."],
    deps = ["//:pi"],
)
