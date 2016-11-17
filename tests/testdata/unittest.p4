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

table MixMany {
    reads {
        header_test.field32 : exact;
        header_test.field16 : lpm;
        header_test.field20 : ternary;
        header_test : valid;
    }
    actions {
        actionA;
    }
    size: 512;
}

control ingress {
    apply(ExactOne);
    apply(LpmOne);
    apply(TernaryOne);
    apply(MixMany);
}

control egress { }
