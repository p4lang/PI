package(
    default_visibility = ["//visibility:public"],
)

cc_library(
    name = "pifeproto",
    srcs = glob(["src/*.cpp", "src/*.h"]),
    hdrs = ["PI/frontends/proto/device_mgr.h",
            "PI/frontends/proto/logging.h"],
    includes = ["."],
    copts = ["-DUSE_ABSL=1"],
    deps = ["@com_github_p4lang_p4runtime//:p4runtime_cc_grpc",
            "@com_github_openconfig_gnmi//:gnmi_cc_grpc",
            "@com_github_googleapis//:code_cc_proto",
            "//proto:piprotoutil",
            "//proto/third_party:fmt",
            "//proto:p4config_cc_proto",
            "//frontends_extra/cpp:pifecpp",
            "//proto/p4info:piconvertproto",
            "@com_google_absl//absl/synchronization:synchronization"],
)
