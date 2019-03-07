package(
    default_visibility = ["//visibility:public"],
)

filegroup(
    name = "pihdrs",
    srcs = glob(["include/**/*.h"]),
    visibility = ["//:__subpackages__"],
)

cc_library(
    name = "piutils",
    srcs = glob(["src/utils/*.c"]) + ["//:pihdrs"],
    hdrs = glob(["src/utils/*.h"]),
    includes = ["src/utils", "include"],
    deps = [],
    visibility = ["//:__subpackages__"],
)


cc_library(
    name = "pip4info",
    srcs = ["src/p4info_int.h", ":pihdrs"]
        + glob(["src/p4info/*.c", "src/p4info/*.h"])
        + glob(["src/config_readers/*.c", "src/config_readers/*.h"]),
    hdrs = glob(["include/PI/p4info/*.h"]),
    includes = ["include", "src"],
    copts = ["-DPI_LOG_ON"],
    deps = ["//third_party/cJSON:picjson",
            "//lib:pitoolkit",
            ":piutils",
            "@judy//:Judy1",
            "@judy//:JudyL",
            "@judy//:JudySL"],
)

# using glob looks a bit nasty because of the files we have to exclude, but in
# the absence of a CI for the Bazel build, it is less error-prone that listing
# all files manually.
cc_library(
    name = "pi",
    srcs = [":pihdrs"]
        + glob(["src/*.c"], exclude=[
              "src/pi_notifications_pub.c", "src/pi_rpc_server.c"])
        + glob(["src/*.h"], exclude=[
              "src/p4info_int.h", "src/pi_notifications_pub.h"]),
    hdrs = glob(["include/PI/*.h", "include/PI/target/*.h"])
        + ["include/PI/int/pi_int.h", "include/PI/int/serialize.h"],
    includes = ["include"],
    deps = [":pip4info",
            "@judy//:JudyL",
            "@judy//:JudySL"],
)

cc_library(
    name = "pifegeneric",
    srcs = ["src/frontends/generic/pi.c"],
    hdrs = ["include/PI/frontends/generic/pi.h"],
    includes = ["include"],
    copts = ["-DPI_LOG_ON"],
    deps = [":pi"],
)