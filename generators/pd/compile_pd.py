#!/usr/bin/env python2

################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2015-2016 Barefoot Networks, Inc.
#
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material is strictly
# forbidden unless prior written permission is obtained from Barefoot Networks,
# Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a
# written agreement with Barefoot Networks, Inc.
#
###############################################################################

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

# TEMPORARY script for testing and debuggin

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
