"""Load dependencies needed to compile PI as a 3rd-party consumer."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("//bazel:workspace_rule.bzl", "remote_workspace")

GNMI_COMMIT = "39cb2fffed5c9a84970bde47b3d39c8c716dc17a";
GNMI_SHA = "3701005f28044065608322c179625c8898beadb80c89096b3d8aae1fbac15108";
P4RUNTIME_TAG = "1.2.0"
P4RUNTIME_SHA="0fce7e06c63e60a8cddfe56f3db3d341953560c054d4c09ffda0e84476124f5a"

def PI_deps():
    """Loads dependencies needed to compile PI."""

    if "com_github_p4lang_p4runtime" not in native.existing_rules():
        http_archive(
            name = "com_github_p4lang_p4runtime",
            urls = ["https://github.com/p4lang/p4runtime/archive/v%s.zip" % P4RUNTIME_TAG],
            sha256 = P4RUNTIME_SHA,
            strip_prefix = "p4runtime-%s/proto" % P4RUNTIME_TAG,
        )

    if "judy" not in native.existing_rules():
        http_archive(
            name = "judy",
            build_file = "@com_github_p4lang_PI//bazel/external:judy.BUILD",
            url = "http://archive.ubuntu.com/ubuntu/pool/universe/j/judy/judy_1.0.5.orig.tar.gz",
            sha256 = "d2704089f85fdb6f2cd7e77be21170ced4b4375c03ef1ad4cf1075bd414a63eb",
            strip_prefix = "judy-1.0.5",
        )

    if "com_google_absl" not in native.existing_rules():
        remote_workspace(
            name = "com_google_absl",
            remote = "https://github.com/abseil/abseil-cpp",
            branch = "lts_2019_08_08",
        )

    if "com_github_openconfig_gnmi" not in native.existing_rules():
        http_archive(
            name = "com_github_openconfig_gnmi",
            url = "https://github.com/openconfig/gnmi/archive/%s.zip" % GNMI_COMMIT,
            sha256 = GNMI_SHA,
            strip_prefix = "gnmi-%s/proto" % GNMI_COMMIT,
            build_file = "@//bazel:external/gnmi.BUILD",
            patch_cmds = [
                "sed -i.bak 's#github.com/openconfig/gnmi/proto/##g' gnmi/gnmi.proto",
                "rm gnmi/gnmi.proto.bak"
            ],
        )

    if "com_google_googletest" not in native.existing_rules():
        remote_workspace(
            name = "com_google_googletest",
            remote = "https://github.com/google/googletest",
            commit = "f5edb4f542e155c75bc4b516f227911d99ec167c",
        )

    if "com_google_googleapis" not in native.existing_rules():
        remote_workspace(
            name = "com_google_googleapis",
            remote = "https://github.com/googleapis/googleapis",
            commit = "1079c999f0683196d857795ae6951ced9e15ce72",
        )

    if "com_github_nelhage_rules_boost" not in native.existing_rules():
        remote_workspace(
            name = "com_github_nelhage_rules_boost",
            remote = "https://github.com/nelhage/rules_boost",
            commit = "a3b25bf1a854ca7245d5786fda4821df77c57827",
        )
