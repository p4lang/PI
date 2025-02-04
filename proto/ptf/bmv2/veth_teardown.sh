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

noOfVeths=8
if [ $# -eq 1 ]; then
    noOfVeths=$1
fi
echo "No of veth pairs is $noOfVeths"
idx=0
while [ $idx -lt $noOfVeths ]
do
    intf0="veth$(($idx*2))"
    intf1="veth$(($idx*2+1))"
    if ip link show $intf0 &> /dev/null; then
        ip link delete $intf0 type veth
    fi
    if ip link show $intf1 &> /dev/null; then
        ip link delete $intf1 type veth
    fi
    idx=$((idx + 1))
done
