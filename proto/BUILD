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

proto_library(
    name = "p4config_proto",
    srcs = ["p4/tmp/p4config.proto"]
)

cc_proto_library(
    name = "p4config_cc_proto",
    deps = [":p4config_proto"],
)
