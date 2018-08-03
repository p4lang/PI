package(
    default_visibility = ["//:__subpackages__"],
)

licenses(
    ["notice"],  # MIT
)

cc_library(
    name = "picjson",
    srcs = glob(["src/cJSON.c"]),
    hdrs = glob(["include/cJSON/cJSON.h"]),
    includes = ["include", "include/cJSON"],
    deps = [],
)
