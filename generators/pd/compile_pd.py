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

# TEMPORARY script for testing and debugging

import argparse

parser = argparse.ArgumentParser(description='Temporary PD compilation')
parser.add_argument('source', metavar='source', type=str,
                    help='JSON source.')
parser.add_argument('--out', '-o', type=str,
                    help='Directory where source will be auto-generated and '
                    'libraries will be compiled',
                    required=False)
parser.add_argument('--p4-prefix', type=str,
                    help='P4 name use for API function prefix',
                    default="prog", required=False)

import subprocess
import tempfile
import os
import shutil
import fileinput
import sys

args = parser.parse_args()
if not args.out:
    tmp_dir = tempfile.mkdtemp(dir=os.getcwd())
else:
    tmp_dir = os.path.abspath(args.out)
    if os.path.exists(tmp_dir) and not os.path.isdir(tmp_dir):
        print "Invalid out directory"
        sys.exit(1)
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)

with open("native.json", 'w') as f:
    p = subprocess.Popen(["../../bin/pi_gen_native_json", args.source], stdout=f)
    p.wait()

    p = subprocess.Popen(
        ["python2", "gen_pd.py", "--pd", tmp_dir, "--p4-prefix", args.p4_prefix,
         f.name])
    p.wait()

shutil.copy("pd.mk", tmp_dir)
shutil.copy("pdthrift.mk", tmp_dir)
shutil.copy("res.thrift", os.path.join(tmp_dir, "thrift"))
os.chdir(tmp_dir)

subprocess.check_call(["make", "-f", "pd.mk"])
subprocess.check_call(["make", "P4_PREFIX={}".format(args.p4_prefix),
                       "-f", "pdthrift.mk"])
os.chdir(os.pardir)

shutil.copy(os.path.join(tmp_dir, "libpd.so"), os.getcwd())
shutil.copy(os.path.join(tmp_dir, "libpdthrift.so"), os.getcwd())


print "Output generated in", tmp_dir
