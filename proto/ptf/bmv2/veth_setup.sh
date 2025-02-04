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
last=`expr $noOfVeths - 1`
veths=`seq 0 1 $last`

for i in $veths; do
    intf0="veth$(($i*2))"
    intf1="veth$(($i*2+1))"
    if ! ip link show $intf0 &> /dev/null; then
        ip link add name $intf0 type veth peer name $intf1 &> /dev/null
    fi
    ip link set dev $intf0 up
    ip link set dev $intf1 up
    ifconfig $intf0 mtu 10240 up
    ifconfig $intf1 mtu 10240 up
    TOE_OPTIONS="rx tx sg tso ufo gso gro lro rxvlan txvlan rxhash"
    for TOE_OPTION in $TOE_OPTIONS; do
       /sbin/ethtool --offload $intf0 "$TOE_OPTION" off &> /dev/null
       /sbin/ethtool --offload $intf1 "$TOE_OPTION" off &> /dev/null
    done
    sysctl net.ipv6.conf.$intf0.disable_ipv6=1 &> /dev/null
    sysctl net.ipv6.conf.$intf1.disable_ipv6=1 &> /dev/null
done
