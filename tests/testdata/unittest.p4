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

header_type header_test_t {
    fields {
        field8 : 8;
        field16 : 16;
        field20 : 20;
        field24 : 24;
        field32 : 32;
        field48 : 48;
        field64 : 64;
        field12 : 12;
        field4 : 4;
    }
}

header header_test_t header_test;

parser start {
    return ingress;
}

action actionA(param) {
    modify_field(header_test.field48, param);
}

action actionB(param) {
    modify_field(header_test.field8, param);
}

action actionC() { }

table ExactOne {
    reads {
        header_test.field32 : exact;
    }
    actions {
        actionA; actionB;
    }
    size: 512;
}

counter ExactOne_counter {
    type : packets;
    direct : ExactOne;
}

meter ExactOne_meter {
    type : bytes;
    direct : ExactOne;
    result : header_test.field16;
}

table LpmOne {
    reads {
        header_test.field32 : lpm;
    }
    actions {
        actionA;
    }
    size: 512;
}

table TernaryOne {
    reads {
        header_test.field32 : ternary;
    }
    actions {
        actionA;
    }
    size: 512;
}

table TernaryTwo {
    reads {
        header_test.field32 : ternary;
        header_test.field16 : ternary;
    }
    actions {
        actionA;
    }
    size: 512;
}

table RangeOne {
    reads {
        header_test.field32 : range;
    }
    actions {
        actionA;
    }
    size: 512;
}

table MixMany {
    reads {
        header_test.field32 : exact;
        header_test.field16 : lpm;
        header_test.field20 : ternary;
        header_test : valid;
    }
    actions {
        actionA; actionC;
    }
    size: 512;
}

table IndirectWS {
    reads {
        header_test.field32 : exact;
    }
    action_profile: ActProfWS;
    size: 512;
}

action_profile ActProfWS {
    actions {
        actionA;
        actionB;
    }
    size : 128;
    dynamic_action_selection : Selector;
}

action_selector Selector {
    selection_key : SelectorHash;
}

field_list HashFields {
    header_test.field24;
    header_test.field48;
    header_test.field64;
}

field_list_calculation SelectorHash {
    input { HashFields; }
    algorithm : crc16;
    output_width : 16;
}

table ExactOneNonAligned {
    reads {
        header_test.field12 : exact;
    }
    actions {
        actionA; actionB;
    }
    size: 512;
}

counter CounterA {
    type : packets;
    instance_count : 1024;
}

action _CounterAAction() {
    count(CounterA, 128);
}

table _CounterATable {
    reads {
         header_test.field32 : exact;
    }
    actions {
        _CounterAAction;
    }
    size: 512;
}

control ingress {
    apply(ExactOne);
    apply(LpmOne);
    apply(TernaryOne);
    apply(TernaryTwo);
    apply(RangeOne);
    apply(MixMany);
    apply(IndirectWS);
    apply(ExactOneNonAligned);
    apply(_CounterATable);
}

control egress { }
