#! /bin/bash
#
# gen_p4info.sh - Utility to generate P4Info in three different formats from one P4_16 source file.
#

# Copyright 2018-present Keysight Technologies, Inc.
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
# Chris Sommers (chris.sommers@keysight.com)
#
if [ $# -ne 1 ]; then
	echo "USAGE: $0 <p4 source file>"
	exit 1
fi

echo "Generating $1.p4info.proto ..."
echo "p4c-bm2-ss --p4runtime-file $1.p4info.proto --p4runtime-format binary $1"
p4c-bm2-ss --p4runtime-file $1.p4info.proto --p4runtime-format binary $1
echo "Generating $1.p4info.json ..."
echo "p4c-bm2-ss --p4runtime-file $1.p4info.json --p4runtime-format json $1"
p4c-bm2-ss --p4runtime-file $1.p4info.json --p4runtime-format json $1
echo "Generating $1.p4info.txt ..."
echo "p4c-bm2-ss --p4runtime-file $1.p4info.txt --p4runtime-format text $1"
p4c-bm2-ss --p4runtime-file $1.p4info.txt --p4runtime-format text $1