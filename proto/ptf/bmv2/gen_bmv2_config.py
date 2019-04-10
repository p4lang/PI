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

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

def check_compiler_exec(path):
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.check_call([path, '--version'],
                                  stdout=devnull, stderr=devnull)
        return True
    except subprocess.CalledProcessError:
        return True
    except OSError:  # exec not found
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Invokes the p4c-bm2-ss compiler and generates a "
        "binary file to be used as the 'p4_device_config' field in the "
        "ForwardingPipelineConfig p4runtime.proto message.")
    parser.add_argument('src', type=str,
                        help='Path to P4 source')
    parser.add_argument('--out-bin', type=str, required=True,
                        help='Path for output binary file')
    parser.add_argument('--out-p4info', type=str, required=True,
                        help='Path for output p4info text message')
    parser.add_argument('--compiler', type=str, default='p4c-bm2-ss',
                        help='bmv2 compiler to use. Default is p4c-bm2-ss.')
    args = parser.parse_args()

    if not check_compiler_exec(args.compiler):
        print "Cannot use provided compiler or compiler binary not in PATH"
        sys.exit(1)

    if not os.path.exists(args.src):
        print "P4 source", args.src, "does not exist"
        sys.exit(1)

    tmp_dir = tempfile.mkdtemp()
    out_json = os.path.join(tmp_dir, 'dp.json')
    out_p4info = os.path.join(tmp_dir, 'p4info.proto.txt')
    cmd = [args.compiler, '--std', 'p4-16', args.src, '-o', out_json,
           '--p4runtime-format', 'text', '--p4runtime-file', out_p4info]
    print ' '.join(cmd)
    try:
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        print "Error when compiling P4 program"
        shutil.rmtree(tmp_dir)
        sys.exit(1)
    except OSError:
        print "Fatal error when compiling P4 program"
        shutil.rmtree(tmp_dir)
        sys.exit(2)

    try:
        shutil.copyfile(out_p4info, args.out_p4info)
    except:
        print "Error when writing to", args.out_p4info
        sys.exit(1)

    try:
        shutil.copyfile(out_json, args.out_bin)
    except:
        print "Error when writing to", args.out_bin
        sys.exit(1)

    shutil.rmtree(tmp_dir)

if __name__ == '__main__':
    main()
