"""Load dependencies needed to compile PI as a 3rd-party consumer."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("//bazel:workspace_rule.bzl", "remote_workspace")

GNMI_COMMIT="39cb2fffed5c9a84970bde47b3d39c8c716dc17a";
GNMI_SHA="3701005f28044065608322c179625c8898beadb80c89096b3d8aae1fbac15108";

# P4RUNTIME_TAG = "1.3.0"
# We cannot use the latest release (v1.3.0) as we need to include a recent fix
# to support Bazel 4.0. More precisely, this fix updates the Bazel build
# dependencies to more recent versions compatible with Bazel 4.0.
P4RUNTIME_COMMIT="e9c0d196c4c2acd6f1bd3439f5b30b423ef90c95"
P4RUNTIME_SHA="c83ab6b7f89e5d1a0faedb04d6a0e3c2969a810f98d732bca40c8d774851aedb"

def PI_deps():
    """Loads dependencies needed to compile PI."""

    if "com_github_p4lang_p4runtime" not in native.existing_rules():
        http_archive(
            name = "com_github_p4lang_p4runtime",
            # urls = ["https://github.com/p4lang/p4runtime/archive/v%s.zip" % P4RUNTIME_TAG],
            urls = ["https://github.com/p4lang/p4runtime/archive/%s.zip" % P4RUNTIME_COMMIT],
            sha256 = P4RUNTIME_SHA,
            # strip_prefix = "p4runtime-%s/proto" % P4RUNTIME_TAG,
            strip_prefix = "p4runtime-%s/proto" % P4RUNTIME_COMMIT,
        )

    if "com_google_absl" not in native.existing_rules():
        remote_workspace(
            name = "com_google_absl",
            remote = "https://github.com/abseil/abseil-cpp",
            branch = "lts_2020_09_23",
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
            commit = "8fa381b7138f1d72966ff20563efae1b2194d359",
        )

    if "com_github_nelhage_rules_boost" not in native.existing_rules():
        remote_workspace(
            name = "com_github_nelhage_rules_boost",
            remote = "https://github.com/nelhage/rules_boost",
            commit = "a3b25bf1a854ca7245d5786fda4821df77c57827",
        )
