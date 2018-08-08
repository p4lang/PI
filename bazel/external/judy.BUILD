package(
    default_visibility = [ "//visibility:public" ],
)

config_setting(
    name = "x86_32_build",
    constraint_values = ["@bazel_tools//platforms:x86_32"],
)

config_setting(
    name = "x86_64_build",
    constraint_values = ["@bazel_tools//platforms:x86_64"],
)

DEFAULT_COPTS = ["-Iexternal/judy/src/JudyCommon"] + select({
    "x86_32_build": ["-DJU_32BIT=1"],
    "x86_64_build": ["-DJU_64BIT=1"],
})

filegroup(
    name = "Judy1_int_hdrs",
    srcs = ["src/Judy1/Judy1.h",
            "src/JudyCommon/JudyPrivate.h",
            "src/JudyCommon/JudyPrivateBranch.h",
            "src/JudyCommon/JudyPrivate1L.h"],
)

cc_binary(
    name = "Judy1TablesGen",
    srcs = ["src/JudyCommon/JudyTables.c", ":Judy1_int_hdrs"],
    copts = DEFAULT_COPTS + ["-DJUDY1", "-Iexternal/judy/src/Judy1"],
)

genrule(
    name = "_Judy1Tables",
    tools = [":Judy1TablesGen"],
    cmd = "$(location :Judy1TablesGen) && cat Judy1Tables.c > $@",
    outs = ["Judy1Tables.c"],
)

cc_library(
    name = "Judy1Prev",
    srcs = ["src/JudyCommon/JudyPrevNext.c",
            "src/JudyCommon/JudyPrevNextEmpty.c",
            ":Judy1_int_hdrs"],
    includes = ["src"],
    copts = DEFAULT_COPTS + ["-DJUDY1", "-DJUDYNEXT", "-Iexternal/judy/src/Judy1"],
)

cc_library(
    name = "Judy1Next",
    srcs = ["src/JudyCommon/JudyPrevNext.c",
            "src/JudyCommon/JudyPrevNextEmpty.c",
            ":Judy1_int_hdrs"],
    includes = ["src"],
    copts = DEFAULT_COPTS + ["-DJUDY1", "-DJUDYPREV", "-Iexternal/judy/src/Judy1"],
)

cc_library(
    name = "Judy1",
    srcs = glob(["src/JudyCommon/*.c", "src/JudyCommon/*.h"], exclude = ["src/JudyCommon/JudyPrintJP.c"])
        + ["src/Judy1/Judy1.h", "Judy1Tables.c"],
    hdrs = ["src/Judy.h"],
    copts = DEFAULT_COPTS + ["-DJUDY1", "-Iexternal/judy/src/Judy1"],
    includes = ["src"],
    deps = [":Judy1Prev", ":Judy1Next"],
)

filegroup(
    name = "JudyL_int_hdrs",
    srcs = ["src/JudyL/JudyL.h",
            "src/JudyCommon/JudyPrivate.h",
            "src/JudyCommon/JudyPrivateBranch.h",
            "src/JudyCommon/JudyPrivate1L.h"],
)

cc_binary(
    name = "JudyLTablesGen",
    srcs = ["src/JudyCommon/JudyTables.c", ":JudyL_int_hdrs"],
    copts = DEFAULT_COPTS + ["-DJUDYL", "-Iexternal/judy/src/JudyL"],
)

genrule(
    name = "_JudyLTables",
    tools = [":JudyLTablesGen"],
    cmd = "$(location :JudyLTablesGen) && cat JudyLTables.c > $@",
    outs = ["JudyLTables.c"],
)

cc_library(
    name = "JudyLPrev",
    srcs = ["src/JudyCommon/JudyPrevNext.c",
            "src/JudyCommon/JudyPrevNextEmpty.c",
            ":JudyL_int_hdrs"],
    includes = ["src"],
    copts = DEFAULT_COPTS + ["-DJUDYL", "-DJUDYNEXT", "-Iexternal/judy/src/JudyL"],
)

cc_library(
    name = "JudyLNext",
    srcs = ["src/JudyCommon/JudyPrevNext.c",
            "src/JudyCommon/JudyPrevNextEmpty.c",
            ":JudyL_int_hdrs"],
    includes = ["src"],
    copts = DEFAULT_COPTS + ["-DJUDYL", "-DJUDYPREV", "-Iexternal/judy/src/JudyL"],
)

cc_library(
    name = "JudyL",
    srcs = glob(["src/JudyCommon/*.c", "src/JudyCommon/*.h"], exclude = ["src/JudyCommon/JudyPrintJP.c"])
        + ["src/JudyL/JudyL.h", "JudyLTables.c"],
    hdrs = ["src/Judy.h"],
    copts = DEFAULT_COPTS + ["-DJUDYL", "-Iexternal/judy/src/JudyL"],
    includes = ["src"],
    deps = [":JudyLPrev", ":JudyLNext"],
)

cc_library(
    name = "JudySL",
    srcs = ["src/JudySL/JudySL.c"],
    hdrs = ["src/Judy.h"],
    copts = DEFAULT_COPTS + ["-Iexternal/judy/src/JudySL"],
    includes = ["src"],
    deps = [":JudyL"],
)
