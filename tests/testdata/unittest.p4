/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// To re-generate the P4Info (unittest.p4info.txt) and the static table entries
// (unittest.entries.txt), run:
// p4test unittest.p4 --std p4-16 --p4runtime-format text --p4runtime-file unittest.p4info.txt --p4runtime-entries-file unittest.entries.txt

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

struct headers_t {
    @name(".header_test")
    header_test_t header_test;
}

struct metadata_t { }

struct test_digest_t {
    bit<48> f48;
    bit<12> f12;
}

parser ParserImpl(packet_in packet, out headers_t hdr, inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    state start {
        transition accept;
    }
}

control ingress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    test_digest_t test_digest;

    @name(".actionA")
    action actionA(bit<48> param) {
        hdr.header_test.field48 = param;
    }
    @name(".actionB")
    action actionB(bit<8> param) {
        hdr.header_test.field8 = param;
    }
    @name(".actionC")
    action actionC() { }

    @name(".ExactOne_counter")
    direct_counter(CounterType.packets) ExactOne_counter;

    // TODO(antonin): meter result should be read in ExactOne's actions; but the
    // p4test backend does not seem to complain or optimize the meter out and
    // the p4info is generated correctly.
    @name(".ExactOne_meter")
    direct_meter<bit<32> >(MeterType.bytes) ExactOne_meter;

    @name(".ExactOne")
    table ExactOne {
        key = {
            hdr.header_test.field32 : exact;
        }
        actions = { actionA; actionB; }
        size = 512;
        counters = ExactOne_counter;
        meters = ExactOne_meter;
    }

    @name(".LpmOne")
    table LpmOne {
        key = {
            hdr.header_test.field32 : lpm;
        }
        actions = { actionA; }
        size = 512;
    }

    @name(".TernaryOne")
    table TernaryOne {
        key = {
            hdr.header_test.field32 : ternary;
        }
        actions = { actionA; }
        size = 512;
    }

    @name(".TernaryTwo")
    table TernaryTwo {
        key = {
            hdr.header_test.field32 : ternary;
            hdr.header_test.field16 : ternary;
        }
        actions = { actionA; }
        size = 512;
    }

    @name(".RangeOne")
    table RangeOne {
        key = {
            hdr.header_test.field32 : range;
        }
        actions = { actionA; }
        size = 512;
    }

    @name(".MixMany")
    table MixMany {
        key = {
            hdr.header_test.field32 : exact;
            hdr.header_test.field16 : lpm;
            hdr.header_test.field20 : ternary;
            hdr.header_test.isValid() : exact;
        }
        actions = { actionA; actionC; }
        size = 512;
    }

    @name(".ActProfWS")
    action_selector(HashAlgorithm.crc16, 32w128, 32w16) ActProfWS;

    @name(".IndirectWS")
    table IndirectWS {
        key = {
            hdr.header_test.field32 : exact;
            hdr.header_test.field24 : selector;
            hdr.header_test.field48 : selector;
            hdr.header_test.field64 : selector;
        }
        actions = { actionA; actionB; }
        implementation = ActProfWS;
        size = 512;
    }

    @name(".ExactOneNonAligned")
    table ExactOneNonAligned {
        key = {
            hdr.header_test.field12 : exact;
        }
        actions = { actionA; actionB; }
        size = 512;
    }

    @name(".CounterA")
    counter(32w1024, CounterType.packets) CounterA;

    @name(".MeterA")
    meter(32w1024, MeterType.packets) MeterA;

    @name(".ConstTable")
    table ConstTable {
        key = {
            hdr.header_test.field16 : exact;
        }
        actions = { actionA; actionB; }
        const entries = {
            (0x01) : actionB(8w01);
            (0x02) : actionB(8w02);
            (0x03) : actionB(8w03);
        }
    }

    @name(".ActionsAnnotationsTable")
    table ActionsAnnotationsTable {
        key = {
            hdr.header_test.field16 : exact;
        }
        actions = { actionA; @tableonly actionB; @defaultonly actionC; }
        size = 512;
    }

    @name(".ConstDefaultActionTable")
    table ConstDefaultActionTable {
        key = {
            hdr.header_test.field16 : exact;
        }
        actions = { actionC; @defaultonly actionB; }
        const default_action = actionB(8w01);
        size = 512;
    }

    @name(".IdleTimeoutTable")
    table IdleTimeoutTable {
        key = {
            hdr.header_test.field16 : exact;
        }
        actions = { actionA; actionB; }
        size = 512;
        support_timeout = true;
    }

    apply {
        ExactOne.apply();
        LpmOne.apply();
        TernaryOne.apply();
        TernaryTwo.apply();
        RangeOne.apply();
        MixMany.apply();
        IndirectWS.apply();
        ExactOneNonAligned.apply();
        CounterA.count(32w128);
        MeterA.execute_meter(32w128, hdr.header_test.field4);
        ConstTable.apply();
        ActionsAnnotationsTable.apply();
        ConstDefaultActionTable.apply();
        IdleTimeoutTable.apply();

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
