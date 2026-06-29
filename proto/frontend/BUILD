# SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "pifeproto",
    srcs = glob([
        "src/*.cpp",
        "src/*.h",
    ]),
    hdrs = [
        "PI/frontends/proto/device_mgr.h",
        "PI/frontends/proto/logging.h",
    ],
    includes = ["."],
    deps = [
        "//frontends_extra/cpp:pifecpp",
        "//proto:p4config_cc_proto",
        "//proto:p4serverconfig_cc_proto",
        "//proto:piprotoserverconfig",
        "//proto:piprotoutil",
        "//proto/p4info:piconvertproto",
        "//proto/third_party:fmt",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_p4lang_p4runtime//proto/p4/v1:p4runtime_cc_grpc",
        "@com_github_p4lang_p4runtime//proto/p4/v1:p4runtime_cc_proto",
        "@com_google_googleapis//google/rpc:code_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)
