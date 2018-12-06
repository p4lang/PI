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

# not using glob to list all .h / .c files since a few files are excluded on
# purpose
cc_library(
    name = "pi",
    srcs = ["src/pi.c",
            "src/pi_tables.c",
            "src/pi_act_prof.c",
            "src/pi_clone.c",
            "src/pi_counter.c",
            "src/pi_meter.c",
            "src/pi_learn.c",
            "src/pi_learn_int.h",
            "src/pi_value.c",
            "src/pi_mc.c",
            "src/device_map.c",
            "src/device_map.h",
            ":pihdrs"],
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