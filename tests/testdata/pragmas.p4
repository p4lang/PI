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
@pragma my_pragma v1
header_type h_t { fields { f32 : 32; } }

@pragma dont_trim
@pragma my_pragma v1
@pragma id 1
header h_t h;

@pragma dont_trim
@pragma my_pragma v1
@pragma id 2 3 4
header h_t hs[3];

// header stack for which we don't provide an id for all instances
@pragma dont_trim
@pragma id 22
header h_t hs2[3];

@pragma my_pragma v1
parser_value_set pv;

@pragma my_pragma v1
parser start {
    return select(standard_metadata.ingress_port) {
        pv : ingress;
        default : ingress;
    }
}

@pragma dont_trim
@pragma my_pragma v1
@pragma id 5
meter m {
    type : packets;
    instance_count : 16;
}

@pragma dont_trim
@pragma id 6
counter c {
    type : packets;
    instance_count : 16;
}

@pragma dont_trim
@pragma my_pragma v1
register r {
    width : 32;
    instance_count : 16;
}

@pragma my_pragma v1
@pragma id 7
field_list flist { h.f32; }

@pragma dont_trim
@pragma my_pragma v1
field_list_calculation calc {
    input { flist; }
    algorithm : csum16;
    output_width : 16;
}

@pragma my_pragma v1
@pragma id 8
action a(ap) {
    modify_field(h.f32, ap);
}

@pragma my_pragma v1
@pragma id 9
table t { actions { a; } }

@pragma id 10
table t2 { action_profile: ap; }

// no support for action profile pragmas yet, so the table (t2) one will be used
@pragma id 11
action_profile ap {
    actions { a; }
    size : 128;
}

@pragma my_pragma v1
control ingress { apply(t); apply(t2); }
