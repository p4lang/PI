# PI LIBRARY REPOSITORY

[![Build Status](https://travis-ci.org/p4lang/PI.svg?branch=main)](https://travis-ci.org/p4lang/PI)

**This repository has submodules; after cloning it you should run `git submodule
  update --init --recursive`.**

## Dependencies

### Base dependencies

- Judy

### Dependencies based on configure flags

Based on the command-line flags you intend on providing to `configure`, you need
to install different dependencies.

| Configure flag        | Default (yes / no) | Dependencies | Remarks |
| --------------------- | --- | --- | --- |
| `--with-bmv2`         | no  | bmv2 and its deps | Implies `--with-fe-cpp` |
| `--with-proto`        | no  | Protobuf, gRPC, libboost-thread-dev | - |
| `--with-fe-cpp`       | no  | - | - |
| `--with-internal-rpc` | no  | nanomsg | - |
| `--with-cli`          | no  | readline | - |
| `--with-sysrepo`      | no  | same as `--with-proto` + sysrepo and its deps| - |

### Additional CI tests dependencies

- libtool binary; we use libtool as part of the build system, libtool binary is
  required to run some of the generated binaries uner valgrind
- valgrind, as some tests use it to check for memory errors
- Boost library, for some of the C++ tests: we currently require
  `boost/optional.hpp` and `boost/functional/hash.hpp`

### Installing dependencies from package repositories

| Dependency | Name of Debian package |
| ---------- | ---------------------- |
| [Judy](http://judy.sourceforge.net/) | libjudy-dev |
| [readline](https://tiswww.case.edu/php/chet/readline/rltop.html) | libreadline-dev |
| valgrind | valgrind |
| libtool binary | libtool-bin |
| Boost library | libboost-dev libboost-system-dev libboost-thread-dev |

### Installing other dependencies from source

Some dependencies are not available as Debian packages or the available version
is not the right one.

- [bmv2](https://github.com/p4lang/behavioral-model) and all its dependencies:
  follow instructions in the [bmv2
  README](https://github.com/p4lang/behavioral-model/blob/master/README.md)
- [nanomsg 1.0.0](https://github.com/nanomsg/nanomsg/releases/tag/1.0.0)
- [Protobuf v3.6.1](https://github.com/google/protobuf/releases/tag/v3.6.1):
```
git clone https://github.com/google/protobuf.git
cd protobuf/
git checkout tags/v3.6.1
./autogen.sh
./configure
make
[sudo] make install
[sudo] ldconfig
```
- [gRPC v1.17.2](https://github.com/grpc/grpc/releases/tag/v1.17.2):
```
git clone https://github.com/google/grpc.git
cd grpc/
git checkout tags/v1.17.2
git submodule update --init --recursive
make
[sudo] make install
[sudo] ldconfig
```
- [sysrepo](https://github.com/sysrepo/sysrepo) and all its dependencies: see
  instructions in [proto/README.md](proto/README.md)

You may be able to use different versions of Protobuf / gRPC, or a more recent
version of nanomsg. However, the versions above are the ones we use for
development and CI testing. When running `configure` with `--with-proto`, the
script will verify that Protobuf >= 3.0.0 and gRPC >= 1.3.0 are installed.

## Building p4runtime.proto

To include `p4runtime.proto` in the build, please run `configure` with
`--with-proto`.

```
./autogen.sh
./configure --with-proto
make
make check
[sudo] make install
```

## Bazel support

We include **tentative** support for the [Bazel](https://bazel.build/) build
system. This should enable other Bazel projects to easily import this
repository. For the great majority of users who wish to build and install PI, we
recommend using the autotools-based build system.

We use [bazelisk](https://github.com/bazelbuild/bazelisk) to install Bazel as
part of [CI](.github/workflows/bazel-build.yml). bazelisk will install the
official latest Bazel release.

To build the P4Runtime PI frontend and run the tests:
```
bazel build //proto/frontend:pifeproto
bazel test //proto/tests:pi_proto_tests
```

To use PI in another Bazel project, do the following in your `WORKSPACE` file:
1. Import this project, for example using `git_repository`.
2. Import dependencies:
```
load("//bazel:deps.bzl", "PI_deps")
PI_deps()

# Transitive dependencies

load("@com_github_p4lang_p4runtime//:p4runtime_deps.bzl", "p4runtime_deps")
p4runtime_deps()

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

load("@com_github_nelhage_rules_boost//:boost/boost.bzl", "boost_deps")
boost_deps()
```

## PI CLI

For now the PI CLI supports an experimental version of `table_add` and
`table_delete`. Because these two functions have been implemented in the bmv2 PI
implementation, you can test the PI CLI with the bmv2 `simple_switch`. Assuming
bmv2 is installed on your system, build the PI and the CLI with `./configure
--with-bmv2 --with-cli && make`. You can then experiment with the following
commands:

    simple_switch tests/testdata/simple_router.json  // to start the switch
    ./CLI/pi_CLI_bmv2 -c tests/testdata/simple_router.json  // to start the CLI
    PI CLI> assign_device 0 0 -- port=9090  // 0 0 : device id + config id
    PI CLI> table_add ipv4_lpm 10.0.0.1/24 => set_nhop 10.0.0.1 1
    PI CLI> table_dump ipv4_lpm
    PI CLI> table_delete ipv4_lpm <handle returned by table_add>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
