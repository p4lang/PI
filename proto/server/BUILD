package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "piserver",
    srcs = ["gnmi_dummy.cpp",
            "log.h",
            "pi_server.cpp",
            "shared_mutex.h",
            "uint128.h",
            "uint128.cpp"],
    hdrs = ["PI/proto/pi_server.h", "pi_server_testing.h", "gnmi.h"],
    copts = ["-DUSE_ABSL=1"],
    deps = ["@com_github_p4lang_p4runtime//:p4runtime_cc_grpc",
            "@com_google_googleapis//google/rpc:code_cc_proto",
            "@com_google_protobuf//:protobuf",
            "@com_github_grpc_grpc//:grpc++",
            "@com_github_openconfig_gnmi//:gnmi_cc_grpc",
            "//proto:p4serverconfig_cc_grpc",
            "//proto/frontend:pifeproto",
            "@com_google_absl//absl/synchronization:synchronization"],
)
