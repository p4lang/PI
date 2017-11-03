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

/* Very basic host L3 forwarding. In particular there is no rmac table and no
 * action packet-in / packet-out support.
 */

#include <core.p4>
#include <v1model.p4>

typedef bit<48> EthernetAddress_t;
typedef bit<32> IPv4Address_t;

typedef bit<9> Port_t;

//------------------------------------------------------------------------------
// HEADERS
//------------------------------------------------------------------------------

header ethernet_t {
    EthernetAddress_t dst_addr;
    EthernetAddress_t src_addr;
    bit<16> ethertype;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> checksum;
    IPv4Address_t src_addr;
    IPv4Address_t dst_addr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

struct local_metadata_t { }

//------------------------------------------------------------------------------
// CHECKSUMS
//------------------------------------------------------------------------------

control verifyChecksum(inout headers_t hdr,
                       inout local_metadata_t local_metadata) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
              hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.src_addr, hdr.ipv4.dst_addr
            },
            hdr.ipv4.checksum,
            HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers_t hdr,
                        inout local_metadata_t local_metadata) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
              hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.src_addr, hdr.ipv4.dst_addr
            },
            hdr.ipv4.checksum,
            HashAlgorithm.csum16);
    }
}

//------------------------------------------------------------------------------
// PARSER
//------------------------------------------------------------------------------

#define ETH_TYPE_IPV4 0x0800

parser parserImpl(packet_in packet,
                  out headers_t hdr,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

#define L3_HOST_FWD_SIZE 16384

control ingress(inout headers_t hdr,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {
    action set_nexthop(Port_t port,
                       EthernetAddress_t smac,
                       EthernetAddress_t dmac) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_addr = smac;
        hdr.ethernet.dst_addr = dmac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action drop() { mark_to_drop(); }

    table l3_host_fwd {
        key = {
            hdr.ipv4.dst_addr : exact;
        }
        actions = { set_nexthop; drop; }
        const default_action = drop();
        size = L3_HOST_FWD_SIZE;
    }

    apply {
        if (hdr.ipv4.ttl > 1) {
            l3_host_fwd.apply();
        } else {
            mark_to_drop();
        }
     }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control egress(inout headers_t hdr,
               inout local_metadata_t local_metadata,
               inout standard_metadata_t standard_metadata) {
    apply { }
}

//------------------------------------------------------------------------------
// DEPARSER
//------------------------------------------------------------------------------

control deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

//------------------------------------------------------------------------------
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

V1Switch(parserImpl(),
         verifyChecksum(),
         ingress(),
         egress(),
         computeChecksum(),
         deparser()) main;
