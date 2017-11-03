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

from functools import wraps
import sys
import threading
import time
import Queue

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils

import grpc

from p4 import p4runtime_pb2
from p4.tmp import p4config_pb2
from p4.config import p4info_pb2
import google.protobuf.text_format

# Convert integer (with length) to binary byte string
# Equivalent to Python 3.2 int.to_bytes
# See
# https://stackoverflow.com/questions/16022556/has-python-3-to-bytes-been-back-ported-to-python-2-7
def stringify(n, length):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s

# This code is common to all tests. setUp() is invoked at the beginning of the
# test and tearDown is called at the end, no matter whether the test passed /
# failed / errored.
class P4RuntimeTest(BaseTest):
    def setUp(self):
        BaseTest.setUp(self)
        self.device_id = 0

        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        self._swports = []
        for device, port, ifname in config["interfaces"]:
            self._swports.append(port)

        grpc_addr = testutils.test_param_get("grpcaddr")
        if grpc_addr is None:
            grpc_addr = 'localhost:50051'

        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = p4runtime_pb2.P4RuntimeStub(self.channel)

        proto_txt_path = testutils.test_param_get("p4info")
        print "Importing p4info proto from", proto_txt_path
        self.p4info = p4info_pb2.P4Info()
        with open(proto_txt_path, "rb") as fin:
            google.protobuf.text_format.Merge(fin.read(), self.p4info)

        # used to store write requests sent to the P4Runtime server, useful for
        # autocleanup of tests (see definition of autocleanup decorator below)
        self._reqs = []

        self.set_up_stream()

    def set_up_stream(self):
        self.stream_out_q = Queue.Queue()
        self.stream_in_q = Queue.Queue()
        def stream_req_iterator():
            while True:
                p = self.stream_out_q.get()
                if p is None:
                    break
                yield p

        def stream_recv(stream):
            for p in stream:
                self.stream_in_q.put(p)

        self.stream = self.stub.StreamChannel(stream_req_iterator())
        self.stream_recv_thread = threading.Thread(
            target=stream_recv, args=(self.stream,))
        self.stream_recv_thread.start()

        self.handshake()

    def handshake(self):
        req = p4runtime_pb2.StreamMessageRequest()
        arbitration = req.arbitration
        arbitration.device_id = self.device_id
        # TODO(antonin): we currently allow 0 as the election id in P4Runtime;
        # if this changes we will need to use an election id > 0 and update the
        # Write message to include the election id
        # election_id = arbitration.election_id
        # election_id.high = 0
        # election_id.low = 1
        self.stream_out_q.put(req)

        rep = self.get_stream_packet("arbitration", timeout=2)
        if rep is None:
            self.fail("Failed to establish handshake")

    def tearDown(self):
        self.tear_down_stream()
        BaseTest.tearDown(self)

    def tear_down_stream(self):
        self.stream_out_q.put(None)
        self.stream_recv_thread.join()

    def get_packet_in(self, timeout=1):
        msg = self.get_stream_packet("packet", timeout)
        if msg is None:
            self.fail("Packet in not received")
        else:
            return msg.packet

    def get_stream_packet(self, type_, timeout=1):
        start = time.time()
        try:
            while True:
                remaining = timeout - (time.time() - start)
                if remaining < 0:
                    break
                msg = self.stream_in_q.get(timeout=remaining)
                if not msg.HasField(type_):
                    continue
                return msg
        except:  # timeout expired
            pass
        return None

    def send_packet_out(self, packet):
        packet_out_req = p4runtime_pb2.StreamMessageRequest()
        packet_out_req.packet.CopyFrom(packet)
        self.stream_out_q.put(packet_out_req)

    def swports(self, idx):
        if idx >= len(self._swports):
            self.fail("Index {} is out-of-bound of port map".format(idx))
            return None
        return self._swports[idx]

    def get_id(self, name, attr):
        for o in getattr(self.p4info, attr):
            pre = o.preamble
            if pre.name == name:
                return pre.id

    def get_table_id(self, name):
        return self.get_id(name, "tables")

    def get_ap_id(self, name):
        return self.get_id(name, "action_profiles")

    def get_action_id(self, name):
        return self.get_id(name, "actions")

    def get_counter_id(self, name):
        return self.get_id(name, "counters")

    def get_direct_counter_id(self, name):
        return self.get_id(name, "direct_counters")

    def get_param_id(self, action_name, name):
        for a in self.p4info.actions:
            pre = a.preamble
            if pre.name == action_name:
                for p in a.params:
                    if p.name == name:
                        return p.id

    def get_mf_id(self, table_name, name):
        for t in self.p4info.tables:
            pre = t.preamble
            if pre.name == table_name:
                for mf in t.match_fields:
                    if mf.name == name:
                        return mf.id

    # These are attempts at convenience functions aimed at making writing
    # P4Runtime PTF tests easier.

    class MF(object):
        def __init__(self, name):
            self.name = name

    class Exact(MF):
        def __init__(self, name, v):
            super(P4RuntimeTest.Exact, self).__init__(name)
            self.v = v

        def add_to(self, mf_id, mk):
            mf = mk.add()
            mf.field_id = mf_id
            mf.exact.value = self.v

    class Lpm(MF):
        def __init__(self, name, v, pLen):
            super(P4RuntimeTest.Lpm, self).__init__(name)
            self.v = v
            self.pLen = pLen

        def add_to(self, mf_id, mk):
            mf = mk.add()
            mf.field_id = mf_id
            mf.lpm.prefix_len = self.pLen
            mf.lpm.value = self.v

    class Ternary(MF):
        def __init__(self, name, v, mask):
            super(P4RuntimeTest.Ternary, self).__init__(name)
            self.v = v
            self.mask = mask

        def add_to(self, mf_id, mk):
            mf = mk.add()
            mf.field_id = mf_id
            mf.ternary.mask = self.mask
            mf.ternary.value = self.v

    # Sets the match key for a p4::TableEntry object. mk needs to be an iterable
    # object of MF instances
    def set_match_key(self, table_entry, t_name, mk):
        for mf in mk:
            mf_id = self.get_mf_id(t_name, mf.name)
            mf.add_to(mf_id, table_entry.match)

    def set_action(self, action, a_name, params):
        action.action_id = self.get_action_id(a_name)
        for p_name, v in params:
            param = action.params.add()
            param.param_id = self.get_param_id(a_name, p_name)
            param.value = v

    # Sets the action & action data for a p4::TableEntry object. params needs to
    # be an iterable object of 2-tuples (<param_name>, <value>).
    def set_action_entry(self, table_entry, a_name, params):
        self.set_action(table_entry.action.action, a_name, params)

    def write_request(self, req, store=True):
        rep = self.stub.Write(req)
        if store:
            self._reqs.append(req)
        return rep

    #
    # Convenience functions to build and send P4Runtime write requests
    #

    def _push_update_member(self, req, ap_name, mbr_id, a_name, params,
                            update_type):
        update = req.updates.add()
        update.type = update_type
        ap_member = update.entity.action_profile_member
        ap_member.action_profile_id = self.get_ap_id(ap_name)
        ap_member.member_id = mbr_id
        self.set_action(ap_member.action, a_name, params)

    def push_update_add_member(self, req, ap_name, mbr_id, a_name, params):
        self._push_update_member(req, ap_name, mbr_id, a_name, params,
                                 p4runtime_pb2.Update.INSERT)

    def send_request_add_member(self, ap_name, mbr_id, a_name, params):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        self.push_update_add_member(req, ap_name, mbr_id, a_name, params)
        return req, self.write_request(req)

    def push_update_modify_member(self, req, ap_name, mbr_id, a_name, params):
        self._push_update_member(req, ap_name, mbr_id, a_name, params,
                                 p4runtime_pb2.Update.MODIFY)

    def send_request_modify_member(self, ap_name, mbr_id, a_name, params):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        self.push_update_modify_member(req, ap_name, mbr_id, a_name, params)
        return req, self.write_request(req, store=False)

    def push_update_add_group(self, req, ap_name, grp_id, grp_size=32,
                              mbr_ids=[]):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        ap_group = update.entity.action_profile_group
        ap_group.action_profile_id = self.get_ap_id(ap_name)
        ap_group.group_id = grp_id
        ap_group.max_size = grp_size
        for mbr_id in mbr_ids:
            member = ap_group.members.add()
            member.member_id = mbr_id

    def send_request_add_group(self, ap_name, grp_id, grp_size=32, mbr_ids=[]):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        self.push_update_add_group(req, ap_name, grp_id, grp_size, mbr_ids)
        return req, self.write_request(req)

    def push_update_set_group_membership(self, req, ap_name, grp_id,
                                         mbr_ids=[]):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.MODIFY
        ap_group = update.entity.action_profile_group
        ap_group.action_profile_id = self.get_ap_id(ap_name)
        ap_group.group_id = grp_id
        for mbr_id in mbr_ids:
            member = ap_group.members.add()
            member.member_id = mbr_id

    def send_request_set_group_membership(self, ap_name, grp_id, mbr_ids=[]):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        self.push_update_set_group_membership(req, ap_name, grp_id, mbr_ids)
        return req, self.write_request(req, store=False)

    #
    # for all add_entry function, use mk == None for default entry
    #
    # TODO(antonin): The current P4Runtime reference implementation on p4lang
    # does not support resetting the default entry (i.e. a DELETE operation on
    # the default entry), which is why we make sure not to include it in the
    # list used for autocleanup, by passing store=False to write_request calls.
    #

    def push_update_add_entry_to_action(self, req, t_name, mk, a_name, params):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        table_entry = update.entity.table_entry
        table_entry.table_id = self.get_table_id(t_name)
        if mk is not None:
            self.set_match_key(table_entry, t_name, mk)
        else:
            table_entry.is_default_action = True
        self.set_action_entry(table_entry, a_name, params)

    def send_request_add_entry_to_action(self, t_name, mk, a_name, params):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        self.push_update_add_entry_to_action(req, t_name, mk, a_name, params)
        return req, self.write_request(req, store=(mk is not None))

    def push_update_add_entry_to_member(self, req, t_name, mk, mbr_id):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        table_entry = update.entity.table_entry
        table_entry.table_id = self.get_table_id(t_name)
        if mk is not None:
            self.set_match_key(table_entry, t_name, mk)
        else:
            table_entry.is_default_action = True
        table_entry.action.action_profile_member_id = mbr_id

    def send_request_add_entry_to_member(self, t_name, mk, mbr_id):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        self.push_update_add_entry_to_member(req, t_name, mk, mbr_id)
        return req, self.write_request(req, store=(mk is not None))

    def push_update_add_entry_to_group(self, req, t_name, mk, grp_id):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        table_entry = update.entity.table_entry
        table_entry.table_id = self.get_table_id(t_name)
        if mk is not None:
            self.set_match_key(table_entry, t_name, mk)
        else:
            table_entry.is_default_action = True
        table_entry.action.action_profile_group_id = grp_id

    def send_request_add_entry_to_group(self, t_name, mk, grp_id):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        self.push_update_add_entry_to_group(req, t_name, mk, grp_id)
        return req, self.write_request(req, store=(mk is not None))

    # iterates over all requests in reverse order; if they are INSERT updates,
    # replay them as DELETE updates; this is a convenient way to clean-up a lot
    # of switch state
    def undo_write_requests(self, reqs):
        updates = []
        for req in reversed(reqs):
            for update in reversed(req.updates):
                if update.type == p4runtime_pb2.Update.INSERT:
                    updates.append(update)
        new_req = p4runtime_pb2.WriteRequest()
        new_req.device_id = self.device_id
        for update in updates:
            update.type = p4runtime_pb2.Update.DELETE
            new_req.updates.add().CopyFrom(update)
        rep = self.stub.Write(new_req)

# this decorator can be used on the runTest method of P4Runtime PTF tests
# when it is used, the undo_write_requests will be called at the end of the test
# (irrespective of whether the test was a failure, a success, or an exception
# was raised). When this is used, all write requests must be performed through
# one of the send_request_* convenience functions, or by calling write_request;
# do not use stub.Write directly!
# most of the time, it is a great idea to use this decorator, as it makes the
# tests less verbose. In some circumstances, it is difficult to use it, in
# particular when the test itself issues DELETE request to remove some
# objects. In this case you will want to do the cleanup yourself (in the
# tearDown function for example); you can still use undo_write_request which
# should make things easier.
# because the PTF test writer needs to choose whether or not to use autocleanup,
# it seems more appropriate to define a decorator for this rather than do it
# unconditionally in the P4RuntimeTest tearDown method.
def autocleanup(f):
    @wraps(f)
    def handle(*args, **kwargs):
        test = args[0]
        assert(isinstance(test, P4RuntimeTest))
        try:
            return f(*args, **kwargs)
        finally:
            test.undo_write_requests(test._reqs)
    return handle
