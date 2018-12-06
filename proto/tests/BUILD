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
            "//proto/frontend:pifeproto"],
    testonly = True,
)

cc_test(
    name = "pi_proto_tests",
    srcs = ["test_p4info_convert.cpp",
            "test_proto_fe.cpp",
            "test_proto_fe_digest.cpp",
            "test_proto_fe_packet_io.cpp",
            "test_proto_fe_set_pipeline_config.cpp",
            "test_task_queue.cpp"],
    deps = ["@com_google_googletest//:gtest",
            "//proto/frontend:pifeproto",
            ":testutils"],
    data = ["//tests:exported_testdata"],
    copts = ['-DTESTDATADIR=\\"tests/testdata\\"'],
)

cc_test(
    name = "pi_proto_server_tests",
    srcs = ["server/test_arbitration.cpp",
            "server/test_gnmi.cpp",
            "server/test_no_pipeline_config.cpp",
            "server/test_pi_server.cpp",
            "server/utils.h",
            "server/utils.cpp"],
    deps = ["@com_google_googletest//:gtest",
            "//proto/server:piserver",
            ":testutils"],
    data = ["//tests:exported_testdata"],
    copts = ['-DTESTDATADIR=\\"tests/testdata\\"',
             "-Iproto/server", "-Iproto/tests"],
)