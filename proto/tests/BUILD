# SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(
    default_visibility = ["//visibility:private"],
)

cc_library(
    name = "testutils",
    testonly = True,
    srcs = [
        "main.cpp",
        "matchers.cpp",
        "mock_switch.cpp",
        "stream_receiver.h",
    ],
    hdrs = [
        "matchers.h",
        "mock_switch.h",
    ],
    deps = [
        "//proto/frontend:pifeproto",
        "@boost.container_hash//:boost.container_hash",
        "@com_github_p4lang_p4runtime//proto/p4/v1:p4runtime_cc_proto",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "pi_proto_tests",
    srcs = [
        "test_p4info_convert.cpp",
        "test_proto_fe_base.h",
        "test_task_queue.cpp",
    ] + glob([
        "test_proto_fe*.cpp",
    ]),
    copts = ['-DTESTDATADIR=\\"tests/testdata\\"'],
    data = ["//tests:exported_testdata"],
    deps = [
        ":testutils",
        "//proto/frontend:pifeproto",
        "@com_github_p4lang_p4runtime//proto/p4/v1:p4runtime_cc_proto",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "pi_proto_server_tests",
    srcs = glob([
        "server/*.cpp",
        "server/*.h",
    ]),
    copts = [
        '-DTESTDATADIR=\\"tests/testdata\\"',
        "-Iproto/server",
        "-Iproto/tests",
        "-I$(GENDIR)/proto/p4serverconfig_cc_grpc_pb/proto",
    ],
    data = ["//tests:exported_testdata"],
    deps = [
        ":testutils",
        "//proto/server:piserver",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_p4lang_p4runtime//proto/p4/v1:p4runtime_cc_grpc",
        "@com_github_p4lang_p4runtime//proto/p4/v1:p4runtime_cc_proto",
        "@com_google_googletest//:gtest",
    ],
)
