#!/usr/bin/env python2

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

from base_test import P4RuntimeTest, autocleanup, stringify, ipv4_to_binary

class L3HostFwdTest(P4RuntimeTest):
    pass

class FwdTest(L3HostFwdTest):
    @autocleanup
    def runTest(self):
        ip_dst_addr = "10.0.0.1"
        ip_dst_addr_str = ipv4_to_binary(ip_dst_addr)
        ig_port = self.swports(1)
        eg_port = self.swports(2)
        # port is 9-bit in v1model, i.e. 2 bytes
        eg_port_str = stringify(eg_port, 2)
        smac = "\xee\xcd\x00\x7e\x70\x00"
        dmac = "\xee\x30\xca\x9d\x1e\x00"

        # we do not care about the src mac address or the src IP address
        pkt = testutils.simple_tcp_packet(
            eth_dst=smac, ip_dst=ip_dst_addr, ip_ttl=64)

        # no forwarding entry: packet must be dropped
        testutils.send_packet(self, ig_port, pkt)
        testutils.verify_no_other_packets(self)

        # add a forwarding entry
        self.send_request_add_entry_to_action(
            "l3_host_fwd", [self.Exact("hdr.ipv4.dst_addr", ip_dst_addr_str)],
            "set_nexthop",
            [("port", eg_port_str), ("smac", smac), ("dmac", dmac)])

        # check that the entry is hit and that no other packets are received
        exp_pkt = testutils.simple_tcp_packet(
            eth_src=smac, eth_dst=dmac, ip_dst=ip_dst_addr, ip_ttl=63)
        testutils.send_packet(self, ig_port, pkt)
        testutils.verify_packets(self, exp_pkt, [eg_port])

class DupEntryTest(L3HostFwdTest):
    @autocleanup
    def runTest(self):
        ip_dst_addr_str = "\x0a\x00\x00\x01"
        eg_port = self.swports(2)
        eg_port_str = stringify(eg_port, 2)
        smac = "\xee\xcd\x00\x7e\x70\x00"
        dmac = "\xee\x30\xca\x9d\x1e\x00"

        def add_entry_once():
            self.send_request_add_entry_to_action(
                "l3_host_fwd",
                [self.Exact("hdr.ipv4.dst_addr", ip_dst_addr_str)],
                "set_nexthop",
                [("port", eg_port_str), ("smac", smac), ("dmac", dmac)])

        add_entry_once()
        with self.assertP4RuntimeError():
            add_entry_once()

class BadMatchKeyTest(L3HostFwdTest):
    @autocleanup
    def runTest(self):
        ip_dst_addr_str = "\x0a\x00\x00\x01"
        bad_ip_dst_addr_str = "\x0a\x00\x00"  # missing one byte
        eg_port = self.swports(2)
        eg_port_str = stringify(eg_port, 2)
        smac = "\xee\xcd\x00\x7e\x70\x00"
        dmac = "\xee\x30\xca\x9d\x1e\x00"

        # missing one byte
        with self.assertP4RuntimeError(code_pb2.INVALID_ARGUMENT):
            self.send_request_add_entry_to_action(
                "l3_host_fwd",
                [self.Exact("hdr.ipv4.dst_addr", bad_ip_dst_addr_str)],
                "set_nexthop",
                [("port", eg_port_str), ("smac", smac), ("dmac", dmac)])

        # unexpected match type
        with self.assertP4RuntimeError(code_pb2.INVALID_ARGUMENT):
            self.send_request_add_entry_to_action(
                "l3_host_fwd",
                [self.Lpm("hdr.ipv4.dst_addr", ip_dst_addr_str, 24)],
                "set_nexthop",
                [("port", eg_port_str), ("smac", smac), ("dmac", dmac)])

class BadChecksumTest(L3HostFwdTest):
    @autocleanup
    def runTest(self):
        # TODO
        pass
