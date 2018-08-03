package(
    default_visibility = [ "//visibility:public" ],
)

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cpp_proto_library")

genrule(
    name = "_copy_gnmi_proto",
    srcs = ["proto/gnmi/gnmi.proto"],
    outs = ["gnmi/gnmi.proto"],
    cmd = "cp $< $@",
)

cpp_proto_library(
    name = "gnmi_cc_grpc",
    protos = ["gnmi/gnmi.proto"],
    imports = ["external/com_google_protobuf/src/"],
    inputs = ["@com_google_protobuf//:well_known_protos"],
    with_grpc = True,
)
