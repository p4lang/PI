workspace(name = "com_github_p4lang_PI")

load("//bazel:deps.bzl", "PI_deps")
PI_deps()

load("@com_github_p4lang_p4runtime//:p4runtime_deps.bzl", "p4runtime_deps")
p4runtime_deps()

# -- Transitive dependencies of P4Runtime dependencies -------------------------

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
protobuf_deps()

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
rules_proto_dependencies()
rules_proto_toolchains()

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")
switched_rules_by_language(
    name = "com_google_googleapis_imports",
    grpc = True,
    cc = True,
    python = True,
)

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
grpc_deps()
load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")
grpc_extra_deps()
load("@com_github_grpc_grpc//bazel:grpc_python_deps.bzl", "grpc_python_deps")
grpc_python_deps()

load("@rules_python//python:pip.bzl", "pip_import", "pip_repositories")
pip_repositories()
pip_import(
    name = "grpc_python_dependencies",
    requirements = "@com_github_grpc_grpc//:requirements.bazel.txt",
)

load("@grpc_python_dependencies//:requirements.bzl", "pip_install")
pip_install()

# -- Boost dependencies -------------------------

load("@com_github_nelhage_rules_boost//:boost/boost.bzl", "boost_deps")
boost_deps()
