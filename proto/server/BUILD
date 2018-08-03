package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "piserver",
    srcs = ["gnmi_dummy.cpp",
            "log.h",
            "pi_server.cpp",
            "uint128.h",
            "uint128.cpp"],
    hdrs = ["PI/proto/pi_server.h", "pi_server_testing.h", "gnmi.h"],
    deps = ["@com_github_p4lang_p4runtime//:p4runtime_cc_grpc",
            "//proto/frontend:pifeproto"],
)
