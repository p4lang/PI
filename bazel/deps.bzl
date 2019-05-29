"""Load dependencies needed to compile PI as a 3rd-party consumer."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("//bazel:workspace_rule.bzl", "remote_workspace")

def PI_deps():
    """Loads dependencies needed to compile PI."""

    if "com_github_p4lang_p4runtime" not in native.existing_rules():
        remote_workspace(
            name = "com_github_p4lang_p4runtime",
            remote = "https://github.com/p4lang/p4runtime",
            # Cannot use 1.0.0 tag, we need a more recent version which includes
            # a Bazel build fix.
            # tag = "1.0.0",
            commit = "98acb3c4ac8337a921b4517fd1979cf23ef52393",
        )

    if "judy" not in native.existing_rules():
        http_archive(
            name = "judy",
            build_file = "@com_github_p4lang_PI//bazel/external:judy.BUILD",
            url = "http://archive.ubuntu.com/ubuntu/pool/universe/j/judy/judy_1.0.5.orig.tar.gz",
            strip_prefix = "judy-1.0.5",
        )

    if "com_google_absl" not in native.existing_rules():
        remote_workspace(
            name = "com_google_absl",
            remote = "https://github.com/abseil/abseil-cpp",
            branch = "master",
        )

    if "com_github_openconfig_gnmi" not in native.existing_rules():
        remote_workspace(
            name = "com_github_openconfig_gnmi",
            remote = "https://github.com/openconfig/gnmi",
            commit = "9c8d9e965b3e854107ea02c12ab11b70717456f2",
            build_file = "bazel/external/gnmi.BUILD",
        )

    if "com_google_googletest" not in native.existing_rules():
        remote_workspace(
            name = "com_google_googletest",
            remote = "https://github.com/google/googletest",
            commit = "f5edb4f542e155c75bc4b516f227911d99ec167c",
        )
