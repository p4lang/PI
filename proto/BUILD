# SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@com_google_protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@com_google_protobuf//bazel:proto_library.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "piprotoutil",
    srcs = ["src/util.cpp"],
    hdrs = ["PI/proto/util.h"],
    includes = ["."],
    deps = ["@com_github_p4lang_p4runtime//proto/p4/config/v1:p4info_cc_proto"],
)

proto_library(
    name = "p4config_proto",
    srcs = ["p4/tmp/p4config.proto"],
)

cc_proto_library(
    name = "p4config_cc_proto",
    deps = [":p4config_proto"],
)

cc_library(
    name = "piprotoserverconfig",
    srcs = ["server_config/server_config.cpp"],
    hdrs = ["server_config/server_config.h"],
    includes = ["."],
    visibility = ["//proto:__subpackages__"],
    deps = [":p4serverconfig_cc_proto"],
)

proto_library(
    name = "p4serverconfig_proto",
    srcs = ["p4/server/v1/config.proto"],
)

cc_proto_library(
    name = "p4serverconfig_cc_proto",
    deps = [":p4serverconfig_proto"],
)

cc_grpc_library(
    name = "p4serverconfig_cc_grpc",
    srcs = [":p4serverconfig_proto"],
    grpc_only = True,
    deps = [":p4serverconfig_cc_proto"],
)

proto_library(
    name = "gnmi_proto",
    srcs = ["openconfig/gnmi/proto/gnmi/gnmi.proto"],
    strip_import_prefix = "openconfig/gnmi/proto",
    deps = [
        "@com_google_protobuf//:any_proto",
        "@com_google_protobuf//:descriptor_proto",
    ],
)

cc_proto_library(
    name = "gnmi_cc_proto",
    deps = [":gnmi_proto"],
)

cc_grpc_library(
    name = "gnmi_cc_grpc",
    srcs = [":gnmi_proto"],
    grpc_only = True,
    deps = [":gnmi_cc_proto"],
)
