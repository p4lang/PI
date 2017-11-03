# P4 Runtime PTF tests

This directory includes [PTF](https://github.com/p4lang/ptf) tests which can be
used to validate the P4 Runtime implementation on a single-device. PTF and these
tests are very similar in spirit to the
[OFTest](https://github.com/floodlight/oftest) framework. This directory is
meant to include several "standard" P4 dataplanes written against the
[v1model.p4](https://github.com/p4lang/p4c/blob/master/p4include/v1model.p4)
reference architecture, with a set of P4 Runtime tests for each of them.

## Running the tests on the bmv2

We use
[simple_switch_grpc](https://github.com/p4lang/behavioral-model/tree/master/targets/simple_switch_grpc),
which is the reference software-switch implementation of the v1model.p4
architecture.

1. Dependencies
- The standard [p4c]((https://github.com/p4lang/p4c) compiler with the bmv2
backend. `p4c-bm2-ss` needs to be in the `PATH`.
- simple_switch_grpc
- [PTF](https://github.com/p4lang/ptf)
- build and install this repository

2. Compiling the P4 program
To compile a P4 program with the [p4c](https://github.com/p4lang/p4c) compiler
bmv2 backend, run:

    ./bmv2/gen_bmv2_config.py l3_host_fwd/l3_host_fwd.p4 \
        --out-bin config.bin --out-p4info p4info.proto.txt

This will generate the P4Info message in text format as well as the
target-specific binary config required to set the forwarding pipeline with P4
Runtime.

3. Create veth interfaces
The following script will create 8 veth pairs. For each pair, one veth will be
used by the simple_switch_grpc process and the other veth will be used by PTF to
inject and receive test packets.

    sudo ./bmv2/veth_setup.sh

4. Start simple_switch_grpc (in one terminal)

    sudo ./bmv2/start_switch.sh

3. Running the PTF tests (in a second terminal)

    sudo python ptf_runner.py \
        --device-config config.bin --p4info p4info.proto.txt \
        --ptfdir l3_host_fwd/test/ --port-map bmv2/port_map.json

## port_map.json

TODO

## writing new PTF tests

TODO
