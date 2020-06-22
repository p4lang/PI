package(
    default_visibility = ["//visibility:public"],
)

load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")

cc_library(
    name = "piprotoutil",
    srcs = ["src/util.cpp"],
    hdrs = ["PI/proto/util.h"],
    includes = ["."],
    deps = ["@com_github_p4lang_p4runtime//:p4info_cc_proto"],
)

proto_library(
    name = "p4config_proto",
    srcs = ["p4/tmp/p4config.proto"]
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
    deps = [":p4serverconfig_cc_proto"],
    visibility = ["//proto:__subpackages__"],
)

proto_library(
    name = "p4serverconfig_proto",
    srcs = ["p4/server/v1/config.proto"]
)

cc_proto_library(
    name = "p4serverconfig_cc_proto",
    deps = [":p4serverconfig_proto"],
)

cc_grpc_library(
    name = "p4serverconfig_cc_grpc",
    srcs = [":p4serverconfig_proto"],
    deps = [":p4serverconfig_cc_proto"],
    grpc_only = True,
)
