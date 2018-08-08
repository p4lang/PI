package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "piprotoutil",
    srcs = ["src/util.cpp"],
    hdrs = ["PI/proto/util.h"],
    includes = ["."],
    deps = ["@com_github_p4lang_p4runtime//:p4info_cc_proto"],
)

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cpp_proto_library")

cpp_proto_library(
  name = "p4config_cc_proto",
  protos = ["p4/tmp/p4config.proto"],
  with_grpc = False,
)
