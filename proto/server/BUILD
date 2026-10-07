# SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "piserver",
    srcs = [
        "gnmi_dummy.cpp",
        "log.h",
        "pi_server.cpp",
        "uint128.cpp",
        "uint128.h",
    ],
    hdrs = [
        "PI/proto/pi_server.h",
        "gnmi.h",
        "pi_server_testing.h",
    ],
    includes = ["."],
    deps = [
        "//proto:gnmi_cc_grpc",
        "//proto:p4serverconfig_cc_grpc",
        "//proto/frontend:pifeproto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_p4lang_p4runtime//proto/p4/v1:p4runtime_cc_grpc",
        "@com_google_googleapis//google/rpc:code_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)
