#!/usr/bin/env bash

# Copyright 2017 Barefoot Networks, Inc.
# SPDX-License-Identifier: Apache-2.0
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

# Antonin Bas (antonin@barefootnetworks.com)

if [ $# -ne 2 ]; then
    echo "Expects exactly 2 arguments"
    echo "Usage: $0 <path to P4 program> <path to output dir>"
    exit 1
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

python3 $THIS_DIR/gen_bmv2_config.py $1 \
  --out-bin $2/device_config.bin --out-p4info $2/p4info.proto.txt
