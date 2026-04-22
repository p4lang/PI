# SPDX-FileCopyrightText: 2018 Antonin Bas
#
# SPDX-License-Identifier: Apache-2.0

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
