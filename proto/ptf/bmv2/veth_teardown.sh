#!/usr/bin/env bash
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
