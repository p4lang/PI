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

import sys
import subprocess
import os
import time
import random
import re

import test_config as cfg

# Class written by Mihai Budiu, for Barefoot Networks, Inc.
class ConcurrentInteger(object):
    # Generates exclusive integers in a range 0-max
    # in a way which is safe across multiple processes.
    # It uses a simple form of locking using folder names.
    # This is necessary because this script may be invoked
    # concurrently many times by make, and we need the many simulator instances
    # to use different port numbers.
    def __init__(self, folder, max):
        self.folder = folder
        self.max = max
    def lockName(self, value):
        return "lock_" + str(value)
    def release(self, value):
        os.rmdir(self.lockName(value))
    def generate(self):
        # try 10 times
        for i in range(0, 10):
            index = random.randint(0, self.max)
            file = self.lockName(index)
            try:
                os.makedirs(file)
                os.rmdir(file)
                return index
            except:
                time.sleep(1)
                continue
        return None

def main():
    def fail(msg):
        print msg
        sys.exit(1)

    if len(sys.argv) != 4:
        fail("Invalid number of arguments")

    testdata_dir = sys.argv[1]
    testname = sys.argv[2]
    jsonname = sys.argv[3]

    command_path = os.path.join(testdata_dir, testname + ".in")
    output_path = os.path.join(testdata_dir, testname + ".out")
    json_path = os.path.join(testdata_dir, jsonname)

    concurrent = ConcurrentInteger(os.getcwd(), 1000)
    rand = concurrent.generate()
    if rand is None:
        fail("Error when generating random port number")
    thrift_port = str(9090 + rand)

    # start simple_switch
    simple_switch_p = subprocess.Popen(
        [cfg.sswitch_path, json_path, "--thrift-port", thrift_port],
        stdout=subprocess.PIPE)

    rpc_server_p = subprocess.Popen([cfg.rpc_server_path],
                                    stdout=subprocess.PIPE)

    time.sleep(1)

    cmd = [cfg.CLI_path, json_path]
    input_ = "select_device 0 port={}\n".format(thrift_port)
    with open(command_path, "r") as f:
        input_ += f.read()

    def cleanup():
        simple_switch_p.kill()
        rpc_server_p.kill()

    out = None
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, _ = p.communicate(input_)
    rc = p.returncode

    if rc:
        cleanup()
        fail("CLI returned error code")

    assert(out)
    # print out

    def parse_data(s, pattern):
        # m = re.findall("{}.*\n(.*)\n(?={})".format(pattern, pattern), s)
        m = re.findall("{}[^\n]*\n(.*?)\n(?={})".format(pattern, pattern), s,
                       re.DOTALL)
        return m

    out_parsed = parse_data(out, "PI CLI> ")

    with open(output_path, "r") as f:
        expected_parse = parse_data(f.read(), "\?\?\?\?")
        if len(out_parsed) != len(expected_parse):
            cleanup()
            fail("Mismatch between expected output and actual output")
        for o, e in zip(out_parsed, expected_parse):
            if o != e:
                cleanup()
                fail("Mismatch between expected output and actual output")

    cleanup()
    sys.exit(0)

if __name__ == '__main__':
    main()
