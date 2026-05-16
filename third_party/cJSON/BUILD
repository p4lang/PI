load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//:__subpackages__"],
)

licenses(
    ["notice"],  # MIT
)

cc_library(
    name = "picjson",
    srcs = ["src/cJSON.c"],
    hdrs = ["include/cJSON/cJSON.h"],
    includes = [
        "include",
        "include/cJSON",
    ],
)
