# SPDX-FileCopyrightText: 2018 Barefoot Networks, Inc.
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library")

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
    includes = [
        "include",
        "src/utils",
    ],
    visibility = ["//:__subpackages__"],
)

cc_library(
    name = "pip4info",
    srcs = [
        "src/p4info_int.h",
        ":pihdrs",
    ] + glob([
        "src/p4info/*.c",
        "src/p4info/*.h",
    ]) + glob([
        "src/config_readers/*.c",
        "src/config_readers/*.h",
    ]),
    hdrs = glob(["include/PI/p4info/*.h"]),
    copts = ["-DPI_LOG_ON"],
    includes = [
        "include",
        "src",
    ],
    deps = [
        ":piutils",
        "//lib:pitoolkit",
        "//third_party:piuthash",
        "//third_party/cJSON:picjson",
    ],
)

# using glob looks a bit nasty because of the files we have to exclude, but in
# the absence of a CI for the Bazel build, it is less error-prone that listing
# all files manually.
cc_library(
    name = "pi",
    srcs = [":pihdrs"] +
           glob(
               ["src/*.c"],
               exclude = [
                   "src/pi_notifications_pub.c",
                   "src/pi_rpc_server.c",
               ],
           ) + glob(
        ["src/*.h"],
        exclude = [
            "src/p4info_int.h",
            "src/pi_notifications_pub.h",
        ],
    ),
    hdrs = glob([
        "include/PI/*.h",
        "include/PI/target/*.h",
    ]) + [
        "include/PI/int/pi_int.h",
        "include/PI/int/serialize.h",
    ],
    includes = ["include"],
    deps = [":pip4info"],
)

cc_library(
    name = "pifegeneric",
    srcs = ["src/frontends/generic/pi.c"],
    hdrs = ["include/PI/frontends/generic/pi.h"],
    copts = ["-DPI_LOG_ON"],
    includes = ["include"],
    deps = [":pi"],
)
