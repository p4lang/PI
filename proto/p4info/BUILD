package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "piconvertproto",
    srcs = ["p4info_to_and_from_proto.cpp"],
    hdrs = ["PI/proto/p4info_to_and_from_proto.h"],
    includes = ["."],
    deps = ["//:pip4info",
            "@com_github_p4lang_p4runtime//:p4info_cc_proto"],
)

cc_binary(
    name = "pi_convert_p4info",
    srcs = ["convert_p4info.cpp"],
    deps = [":piconvertproto"],
)
