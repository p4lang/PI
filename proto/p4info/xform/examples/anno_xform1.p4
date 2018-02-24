//  P4-16 Syntax
//
// Sample P4 program to demonstrate annotation transforms
//
// See https://github.com/p4lang/PI/issues/275
// See https://github.com/p4lang/PI/issues/276
//

// Copyright 2018-present Keysight Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//
// Chris Sommers (chris.sommers@keysight.com)
//

#include <core.p4>
#include <v1model.p4>

typedef bit<9> egress_port_t;
typedef bit<64> register_t;
typedef bit<48> mac_addr_t;
typedef bit<8> flavor_t;

struct routing_metadata_t {
    bit<32> nexthop_ipv4;
}

header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct metadata {
    routing_metadata_t routing_metadata;
    bit<32> hash1;
    bit<32> meter_tag;
    register_t register_val;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state start {
        transition parse_ethernet;
    }
}

// Define an extern to test P4info
extern Flavor<T> {
    Flavor(T flavor);
    void set_flavor(T flavor);
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    @brief("A simple register")
    @description("A simple register longer description")
    @name("my_reg")
    register<register_t>(32w16) my_reg;

    // instantiate an exterm
    @brief("Silly named extern")
    @description("Silly named extern longer description")
    @name("my_flavor")
    Flavor<flavor_t>(8w55) my_flavor;

    @brief("Output packet counts per port - indir")
    @description("Output packet counts per port, indexed by the egress_port, indirect counter")
    @name(".out_count_indirect")
    counter(32w512, CounterType.packets) out_count_indirect;

    @brief("Output packet counts per port, indir")
    @description("Output byte and packet counts per port, indexed by the egress_port, direct counter")
    @name(".out_count_direct")
    direct_counter(CounterType.packets_and_bytes) out_count_direct;

    @name(".rewrite_mac")
    action rewrite_mac(
      @brief("Source MAC address") mac_addr_t smac)
    {
        hdr.ethernet.srcAddr = smac;
        out_count_indirect.count((bit<32>)(bit<32>)standard_metadata.egress_port);
        out_count_direct.count();
    }

    @name("._drop")
    action _drop() {
        mark_to_drop();
    }

    @name(".do_register")
    action do_register(
      @brief("register index") bit<32> index)
    {
      my_reg.read(meta.register_val, index);
    }

    @name(".send_packet_tbl")
    table send_packet_tbl {
        actions = {
            rewrite_mac;
            do_register;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        counters = out_count_direct;
        size = 512;
        default_action = _drop();
    }

    @name(".do_flavor")
    @brief("Action sets the global flavor")
    action do_flavor(
      @brief("Flavor to set") flavor_t the_flavor)
    {
      my_flavor.set_flavor(the_flavor);
    }

    @name(".flavor_tbl")
    table flavor_tbl {
        actions = {
            do_flavor;
        }
        default_action = do_flavor(8w0);
    }

    apply {
       send_packet_tbl.apply();
       flavor_tbl.apply();
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    @name(".set_dmac")
    @brief("Set destination MAC address")
    @description("Set destination MAC address long description")
    action set_dmac(mac_addr_t dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    @name("._drop")
    @brief("Drop packet")
    @brief("Pedantic long description for Drop packet")
    action _drop() {
        mark_to_drop();
    }

    @brief("Set the next hop IP adress and egress port")
    @description("Set the next hop IP adress and egress port longer description")
    @name(".set_nexthop")
    action set_nexthop(
       @brief("Next hop IP address") @description("Next hop IP address longer description") bit<32> nexthop_ipv4,
       @brief("The egress port") @description("The egress port longer description") egress_port_t port)
      {
        meta.routing_metadata.nexthop_ipv4 = nexthop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w63;
    }

    @myanno("forward_tbl anno txt")
    @brief("Forwarding Table")
    @description("Forwarding Table. Based on the next hop, set the mac adress, else drop.")
    @name(".forward_tbl")
    table forward_tbl {
        actions = {
            set_dmac;
            _drop;
        }
        key = {
            meta.routing_metadata.nexthop_ipv4: exact;
        }
        size = 512;
        default_action = _drop();
    }

    @brief("IPv4 LPM lookup brief descrip")
    @description("IPv4 LPM lookup long descrip. Set next hop.")
    @myanno("ipv4_lpm_lkup anno")
    @name(".ipv4_lpm_lkup")
    table ipv4_lpm_lkup {
        actions = {
          @myanno("set_nexthop anno")
            set_nexthop;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm @brief("IPv4 DIP") @description("IPV4 ingress Destination IP Address");
        }
        size = 1024;
        default_action = _drop();
    }

    // action profiles
    @name(".indirect_action_tbl")
    @brief("Indirect action profile")
    @description("Table to test referencing an indirect action profile")
    table indirect_action_tbl {
        key = { }
        actions = { _drop; NoAction; }
        @name("action_profile_wo_selector")
        @brief("Indirect action w/o selector")
        @description("Indirect action w/o selector longer description")
        implementation = action_profile(32w128);
    }

    @name(".indirect_action_tbl_w_selector")
    @brief("Indirect action selector")
    @description("Table to test referencing an indirect action selector")
    table indirect_action_tbl_w_selector {
        key = { meta.hash1 : selector; }
        actions = { _drop; NoAction; }
        @name("action_profile_w_selector")
        @brief("Indirect action w/ selector")
        @description("Indirect action w/ selector longer description")
        implementation = action_selector(HashAlgorithm.identity, 32w1024, 32w10);
    }

    // meters
    @name(".my_meter_direct")
    @brief("Brief descr for direct meter")
    @description("Long description for direct meter")
    direct_meter<bit<32>>(MeterType.packets) my_meter_direct;

    @name(".my_meter_indirect")
    @brief("Brief descr for indirect meter")
    @description("Long description for indirect meter")
    meter(32w16384, MeterType.packets) my_meter_indirect;

    @name(".m_action_direct")
    @brief("Reads direct meter")
    action m_action_direct(
      @brief("The meter index = eggress port num") bit<9> meter_idx)
    {
        my_meter_direct.read(meta.meter_tag);
        standard_metadata.egress_spec = meter_idx;
        standard_metadata.egress_spec = 9w1;
    }

    @name(".m_action_indirect")
    @brief("Executes indirect meter")
    action m_action_indirect(
      @brief("The meter index = eggress port num") bit<9> meter_idx)
    {
        my_meter_direct.read(meta.meter_tag);
        my_meter_indirect.execute_meter((bit<32>)meter_idx, meta.meter_tag);
    }

    @name("._read_dir_meter")
    @brief("Reads a direct meter")
    action _read_dir_meter() {
        my_meter_direct.read(meta.meter_tag);
    }

    @name(".meter_tbl")
    table meter_tbl {
        actions = {
            m_action_direct;
            m_action_indirect;
            _read_dir_meter;
        }
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        size = 1024;
        meters = my_meter_direct;
    }

    // apply
    apply {
        indirect_action_tbl.apply();
        indirect_action_tbl_w_selector.apply();
        meter_tbl.apply();

        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 8w0) {
            ipv4_lpm_lkup.apply();
            forward_tbl.apply();
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
