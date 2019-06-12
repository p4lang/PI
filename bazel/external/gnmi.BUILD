load("@build_stack_rules_proto//cpp:cpp_grpc_library.bzl", "cpp_grpc_library")

package(
    default_visibility = [ "//visibility:public" ],
)

proto_library(
    name = "gnmi_ext_proto",
    srcs = ["gnmi_ext/gnmi_ext.proto"],
)

proto_library(
    name = "gnmi_proto",
    srcs = ["gnmi/gnmi.proto"],
    deps = [
        ":gnmi_ext_proto",
        "@com_google_protobuf//:descriptor_proto",
        "@com_google_protobuf//:any_proto",
    ],
)

cc_proto_library(
    name = "gnmi_ext_cc_proto",
    deps = [":gnmi_ext_proto"]
)

cc_proto_library(
    name = "gnmi_cc_proto",
    deps = ["@com_github_openconfig_gnmi//:gnmi_proto"],
)

cpp_grpc_library(
    name = "gnmi_cc_grpc",
    deps = [":gnmi_proto"],
)