package(
    default_visibility = ["//visibility:public"],
)

# The $(GENDIR)/proto/p4serverconfig_cc_grpc_pb/proto is a hack because of the
# broken Bazel / gRPC support for Protobuf files for which the package path does
# not start at the WORKSPACE root. The strip_import_prefix attribute of the
# proto_library rule works well for cc_proto_library when using a recent Bazel
# version (1.0.1), but not for cc_grpc_library even with a recent gRPC version
# (1.24.3). Maybe when this is fixed
# (https://github.com/grpc/grpc/issues/20675), we can move away from using
# build_stack_rules_proto in p4lang/p4runtime and p4lang/PI and use the official
# gRPC rules.
cc_library(
    name = "piserver",
    srcs = ["gnmi_dummy.cpp",
            "log.h",
            "pi_server.cpp",
            "uint128.h",
            "uint128.cpp"],
    copts = ["-I$(GENDIR)/proto/p4serverconfig_cc_grpc_pb/proto"],
    hdrs = ["PI/proto/pi_server.h", "pi_server_testing.h", "gnmi.h"],
    deps = ["@com_github_p4lang_p4runtime//:p4runtime_cc_grpc",
            "@com_github_openconfig_gnmi//:gnmi_cc_grpc",
            "//proto:p4serverconfig_cc_grpc",
            "//proto/frontend:pifeproto"],
)
