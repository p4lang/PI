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

import sys

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.testutils as testutils

import grpc

from p4 import p4runtime_pb2
from p4.tmp import p4config_pb2
from p4.config import p4info_pb2

# This code is common to all tests. setUp() is invoked at the beginning of the
# test and tearDown is called at the end, no matter whether the test passed /
# failed / errored.
class P4RuntimeTest(BaseTest):
    def setUp(self, proto_bin_path):
        BaseTest.setUp(self)

        self.target = testutils.test_param_get('target')
        if not self.target:
            self.target = "bmv2"
        elif self.target not in {"bmv2"}:
            print "Unsupported target", self.target
            sys.exit(1)

        self.device_id = 0

        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        self.device_id = 0

        self.channel = grpc.insecure_channel('localhost:50051')
        self.stub = p4runtime_pb2.P4RuntimeStub(self.channel)

        ConfigRequest = p4runtime_pb2.SetForwardingPipelineConfigRequest
        req = ConfigRequest()

        print "Connecting to device"
        req.action = ConfigRequest().VERIFY_AND_COMMIT
        config = req.configs.add()
        config.device_id = self.device_id

        print "Importing p4info proto from", proto_bin_path
        with open(proto_bin_path, "rb") as fin:
            config.p4info.ParseFromString(fin.read())

        # we save p4info for name -> id lookups
        self.p4info = config.p4info

        if self.target == "bmv2":
            device_config = p4config_pb2.P4DeviceConfig()
            extras = device_config.extras
            extras.kv["port"] = "9090"
            extras.kv["notifications"] = "ipc:///tmp/bmv2-0-notifications.ipc"
            config.p4_device_config = device_config.SerializeToString()

        rep = self.stub.SetForwardingPipelineConfig(req)

    def tearDown(self):
        BaseTest.tearDown(self)

    def get_id(self, name, attr):
        for o in getattr(self.p4info, attr):
            pre = o.preamble
            if pre.name == name:
                return pre.id

    def get_table_id(self, name):
        return self.get_id(name, "tables")

    def get_action_id(self, name):
        return self.get_id(name, "actions")

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

    # Sets the match key for a p4::TableEntry object. mk needs to be an iterable
    # object of MF instances.
    def set_match_key(self, table_entry, t_name, mk):
        for mf in mk:
            mf_id = self.get_mf_id(t_name, mf.name)
            mf.add_to(mf_id, table_entry.match)

    # Sets the action & action data for a p4::TableEntry object. params needs to
    # be an iterable object of 2-tuples (<param_name>, <value>).
    def set_action_entry(self, table_entry, a_name, params):
        action = table_entry.action.action
        action.action_id = self.get_action_id(a_name)
        for p_name, v in params:
            param = action.params.add()
            param.param_id = self.get_param_id(a_name, p_name)
            param.value = v
