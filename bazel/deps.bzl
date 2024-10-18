"""Load dependencies needed to compile PI as a 3rd-party consumer."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("//bazel:workspace_rule.bzl", "remote_workspace")

GNMI_COMMIT="39cb2fffed5c9a84970bde47b3d39c8c716dc17a";
GNMI_SHA="3701005f28044065608322c179625c8898beadb80c89096b3d8aae1fbac15108";

# P4RUNTIME_TAG = "1.3.0"
# We cannot use the latest release (v1.3.0) as we need to include a recent fix
# to support Bazel 5.0. More precisely, this fix updates the Bazel build
# dependencies to more recent versions compatible with Bazel 5.0.
P4RUNTIME_COMMIT="ec4eb5ef70dbcbcbf2f8357a4b2b8c2f218845a5"
P4RUNTIME_SHA="ea8b7744c45afa7a78a90a1a4232b5fbb386b6714dc16c9b1ea643398889c92b"

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
        http_archive(
            name = "com_google_absl",
            sha256 = "4208129b49006089ba1d6710845a45e31c59b0ab6bff9e5788a87f55c5abd602",
            strip_prefix = "abseil-cpp-20220623.0",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/abseil/abseil-cpp/archive/20220623.0.tar.gz",
                "https://github.com/abseil/abseil-cpp/archive/20220623.0.tar.gz",
            ],
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
            commit = "9fe00a1330817b5ce00919bf2861cd8a9cea1a00",
        )

    if "com_github_nelhage_rules_boost" not in native.existing_rules():
        remote_workspace(
            name = "com_github_nelhage_rules_boost",
            remote = "https://github.com/nelhage/rules_boost",
            commit = "7523a494d35098dfd972399963b00b71064cbb11",
        )
