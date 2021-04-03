#!/usr/bin/env python3

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

import ptf
import os
from ptf import config
import ptf.testutils as testutils

from google.rpc import code_pb2

from base_test import P4RuntimeTest, autocleanup, stringify, ipv4_to_binary, mac_to_binary

class L3HostFwdTest(P4RuntimeTest):
    pass

class FwdTest(L3HostFwdTest):
    @autocleanup
    def runTest(self):
        ip_dst_addr = "10.0.0.1"
        ip_dst_addr_bin = ipv4_to_binary(ip_dst_addr)
        ig_port = self.swports(1)
        eg_port = self.swports(2)
        # port is 9-bit in v1model, i.e. 2 bytes
        eg_port_str = stringify(eg_port, 2)
        smac = "ee:cd:00:7e:70:00"
        dmac = "ee:30:ca:9d:1e:00"
        smac_bin = mac_to_binary(smac)
        dmac_bin = mac_to_binary(dmac)

        # we do not care about the src mac address or the src IP address
        pkt = testutils.simple_tcp_packet(
            eth_dst=smac, ip_dst=ip_dst_addr, ip_ttl=64)

        # no forwarding entry: packet must be dropped
        testutils.send_packet(self, ig_port, pkt)
        testutils.verify_no_other_packets(self)

        # add a forwarding entry
        self.send_request_add_entry_to_action(
            "l3_host_fwd", [self.Exact("hdr.ipv4.dst_addr", ip_dst_addr_bin)],
            "set_nexthop",
            [("port", eg_port_str), ("smac", smac_bin), ("dmac", dmac_bin)])

        # check that the entry is hit and that no other packets are received
        exp_pkt = testutils.simple_tcp_packet(
            eth_src=smac, eth_dst=dmac, ip_dst=ip_dst_addr, ip_ttl=63)
        testutils.send_packet(self, ig_port, pkt)
        testutils.verify_packets(self, exp_pkt, [eg_port])

class DupEntryTest(L3HostFwdTest):
    @autocleanup
    def runTest(self):
        ip_dst_addr = "10.0.0.1"
        ip_dst_addr_bin = ipv4_to_binary(ip_dst_addr)
        eg_port = self.swports(2)
        eg_port_str = stringify(eg_port, 2)
        smac = "ee:cd:00:7e:70:00"
        dmac = "ee:30:ca:9d:1e:00"
        smac_bin = mac_to_binary(smac)
        dmac_bin = mac_to_binary(dmac)

        def add_entry_once():
            self.send_request_add_entry_to_action(
                "l3_host_fwd",
                [self.Exact("hdr.ipv4.dst_addr", ip_dst_addr_bin)],
                "set_nexthop",
                [("port", eg_port_str), ("smac", smac_bin), ("dmac", dmac_bin)])

        add_entry_once()
        with self.assertP4RuntimeError():
            add_entry_once()

class BadMatchKeyTest(L3HostFwdTest):
    @autocleanup
    def runTest(self):
        ip_dst_addr = "10.0.0.1"
        ip_dst_addr_bin = ipv4_to_binary(ip_dst_addr)
        bad_ip_dst_addr_bin = ip_dst_addr_bin[0:3]   # missing one byte
        eg_port = self.swports(2)
        eg_port_str = stringify(eg_port, 2)
        smac = "ee:cd:00:7e:70:00"
        dmac = "ee:30:ca:9d:1e:00"
        smac_bin = mac_to_binary(smac)
        dmac_bin = mac_to_binary(dmac)

        # missing one byte
        with self.assertP4RuntimeError(code_pb2.INVALID_ARGUMENT):
            self.send_request_add_entry_to_action(
                "l3_host_fwd",
                [self.Exact("hdr.ipv4.dst_addr", bad_ip_dst_addr_bin)],
                "set_nexthop",
                [("port", eg_port_str), ("smac", smac_bin), ("dmac", dmac_bin)])

        # unexpected match type
        with self.assertP4RuntimeError(code_pb2.INVALID_ARGUMENT):
            self.send_request_add_entry_to_action(
                "l3_host_fwd",
                [self.Lpm("hdr.ipv4.dst_addr", ip_dst_addr_bin, 24)],
                "set_nexthop",
                [("port", eg_port_str), ("smac", smac_bin), ("dmac", dmac_bin)])

class BadChecksumTest(L3HostFwdTest):
    @autocleanup
    def runTest(self):
        # TODO
        pass
