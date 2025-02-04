/* Copyright 2016 Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
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
// Standard L2 Ethernet header
header_type ethernet_t {
    fields {
        dst_addr        : 48; // width in bits
        src_addr        : 48;
        ethertype       : 16;
    }
}

header ethernet_t ethernet;

header_type h1_t {
    fields {
        f1              : 32;
    }
}

header h1_t h1;

parser start {
    extract(ethernet);
    extract(h1);
    return ingress;
}

action noop() { }

table t1 {
    reads {
        ethernet : valid;
        h1.f1    : valid;
    }
    actions {
        noop;
    }
}

control ingress {
    apply(t1);
}
