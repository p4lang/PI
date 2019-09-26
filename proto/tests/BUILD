package(
    default_visibility = ["//visibility:private"],
)

cc_library(
    name = "testutils",
    srcs = ["main.cpp",
            "matchers.cpp",
            "mock_switch.cpp"],
    hdrs = ["matchers.h", "mock_switch.h"],
    deps = ["@com_google_googletest//:gtest",
            "//proto/frontend:pifeproto",
            "@boost//:optional",
            "@boost//:functional"],
    testonly = True,
)

cc_test(
    name = "pi_proto_tests",
    srcs = ["test_p4info_convert.cpp",
            "test_task_queue.cpp",
            "test_proto_fe_base.h"]
        + glob(["test_proto_fe*.cpp"]),
    deps = ["@com_google_googletest//:gtest",
            "//proto/frontend:pifeproto",
            ":testutils",
            "@boost//:optional"],
    data = ["//tests:exported_testdata"],
    copts = ['-DTESTDATADIR=\\"tests/testdata\\"'],
)

cc_test(
    name = "pi_proto_server_tests",
    srcs = glob(["server/*.cpp", "server/*.h"]),
    deps = ["@com_google_googletest//:gtest",
            "//proto/server:piserver",
            ":testutils",
            "@boost//:optional"],
    data = ["//tests:exported_testdata"],
    copts = ['-DTESTDATADIR=\\"tests/testdata\\"',
             "-Iproto/server", "-Iproto/tests"],
)