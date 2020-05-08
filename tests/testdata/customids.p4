// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// To re-generate the P4Info (customids.p4info.txt), run:
// p4test customids.p4 --std p4-16 --p4runtime-files customids.p4info.txt

#include <v1model.p4>

header header_test_t {
    bit<8> field8;
    bit<16> field16;
    bit<20> field20;
    bit<24> field24;
    bit<32> field32;
    bit<48> field48;
    bit<64> field64;
    bit<12> field12;
    bit<4> field4;
}

@controller_header("packet_in")
header cpu_header_t { bit<32> f1; @id(1) bit<32> f2; }

struct headers_t {
    header_test_t header_test;
    cpu_header_t cpu_header;
}

struct metadata_t { }

struct test_digest_t {
    @id(101) bit<48> f48;
    bit<12> f12;
}

parser ParserImpl(packet_in packet, out headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.cpu_header);
        transition accept;
    }
}

control ingress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    test_digest_t test_digest;

    @name(".actionA")
    @id(1)
    action actionA(@id(101) bit<48> p1, bit<32> p2) {
        hdr.header_test.field48 = p1;
        hdr.header_test.field32 = p2;
    }

    @name(".actionB")
    @id(2)
    action actionB(bit<8> param) {
        hdr.header_test.field8 = param;
    }
    @name(".actionC")
    @id(3)
    action actionC() { }

    @name(".ExactOne")
    @id(1)
    table ExactOne {
        key = {
            hdr.header_test.field64 : exact @id(101);
            hdr.header_test.field12 : exact;
        }
        actions = { actionA; actionB; }
        size = 512;
    }

    apply {
        ExactOne.apply();

        test_digest = {hdr.header_test.field48, hdr.header_test.field12};
        digest(1, test_digest);
    }
}

control egress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply { }
}

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply { }
}

control verifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control computeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}
V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
