# SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "piconvertproto",
    srcs = ["p4info_to_and_from_proto.cpp"],
    hdrs = ["PI/proto/p4info_to_and_from_proto.h"],
    includes = ["."],
    deps = [
        "//:pip4info",
        "@com_github_p4lang_p4runtime//proto/p4/config/v1:p4info_cc_proto",
    ],
)

cc_binary(
    name = "pi_convert_p4info",
    srcs = ["convert_p4info.cpp"],
    deps = [":piconvertproto"],
)
