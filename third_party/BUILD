# SPDX-FileCopyrightText: 2021 Antonin Bas
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_cc//cc:defs.bzl", "cc_library")

package(
    default_visibility = ["//:__subpackages__"],
)

cc_library(
    name = "piuthash",
    hdrs = glob(["uthash/src/*.h"]),
    includes = ["uthash/src"],
)
