# PI LIBRARY REPOSITORY

[![Build Status](https://travis-ci.org/p4lang/PI.svg?branch=master)](https://travis-ci.org/p4lang/PI)

**This repository has submodules; after cloning it you should run `git submodule
  update --init --recursive`.**

See [examples](examples/) for how to use the PI.

## Dependencies

- libjudy-dev
- libreadline-dev

## Building p4runtime.proto

To include `p4runtime.proto` in the build, please run `configure` with
`--with-proto`.

## PI CLI

For now the PI CLI supports an experimental version of `table_add` and
`table_delete`. Because these two functions have been implemented in the bmv2 PI
implementation, you can test the PI CLI with the bmv2 `simple_switch`. Assuming
bmv2 is installed on your system, build the PI and the CLI with `./configure
--with-bmv2 && make`. You can then experiment with the following commands:

    simple_switch tests/testdata/simple_router.json  // to start the switch
    ./CLI/pi_CLI_bmv2 -c tests/testdata/simple_router.json  // to start the CLI
    PI CLI> assign_device 0 0 -- port=9090  // 0 0 : device id + config id
    PI CLI> table_add ipv4_lpm 10.0.0.1/24 => set_nhop 10.0.0.1 1
    PI CLI> table_dump ipv4_lpm
    PI CLI> table_delete ipv4_lpm <handle returned by table_add>

## Contributing

All contributed code must pass the style checker, which can be run with
`./tools/check_style.sh`. If the style checker fails because of a C file, you
can format this C file with `./tools/clang_format_check.py -s Google -i <file>`.
