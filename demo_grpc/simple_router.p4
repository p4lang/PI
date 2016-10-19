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

#define CPU_REASON_NO_ARP_ENTRY 0
#define CPU_REASON_ARP_MSG 1
#define CPU_PORT 64

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

parser start {
    return select(current(0, 64)) {
        0 : parse_cpu_header;
        default: parse_ethernet;
    }
}

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_ARP : parse_arp;
        default: ingress;
    }
}

header ipv4_t ipv4;

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}


header_type arp_t {
    fields {
        hwType : 16;
        protoType : 16;
        hwAddrLen : 8;
        protoAddrLen : 8;
        opcode : 16;
        hwSrcAddr : 48;
        protoSrcAddr : 32;
        hwDstAddr : 48;
        protoDstAddr : 32;
    }
}

header arp_t arp;

parser parse_arp {
    extract(arp);
    return ingress;
}

header_type cpu_header_t {
    fields {
        zeros : 64;
        reason : 16;
        port : 16;
    }
}

header cpu_header_t cpu_header;

parser parse_cpu_header {
    extract(cpu_header);
    return parse_ethernet;
}


action _drop() {
    drop();
}

header_type routing_metadata_t {
    fields {
        nhop_ipv4 : 32;
    }
}

metadata routing_metadata_t routing_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    default_action: _drop();
    size: 1024;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

action do_send_to_cpu(reason, cpu_port) {
    add_header(cpu_header);
    modify_field(cpu_header.reason, reason);
    modify_field(cpu_header.port, standard_metadata.ingress_port);
    modify_field(standard_metadata.egress_spec, cpu_port);
}

table forward {
    reads {
        routing_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        do_send_to_cpu;
        _drop;
    }
    default_action: do_send_to_cpu(CPU_REASON_NO_ARP_ENTRY, CPU_PORT);
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    default_action: _drop();
    size: 256;
}

action do_decap_cpu_header() {
    modify_field(standard_metadata.egress_spec, cpu_header.port);
    remove_header(cpu_header);
}

table decap_cpu_header {
    actions {
        do_decap_cpu_header;
    }
    default_action: do_decap_cpu_header();
}

table send_arp_to_cpu {
    actions {
        do_send_to_cpu;
    }
    default_action: do_send_to_cpu(CPU_REASON_ARP_MSG, CPU_PORT);
}

control ingress {
    if (valid(cpu_header)) {
        apply(decap_cpu_header);
    } else {
        if (valid(arp)) {
            apply(send_arp_to_cpu);
        }
        if(valid(ipv4) and ipv4.ttl > 0) {
            apply(ipv4_lpm);
            apply(forward);
        }
    }
}

control egress {
    if (not valid(cpu_header)) {
        apply(send_frame);
    }
}
