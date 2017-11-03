#!/usr/bin/env bash

if [ $# -ne 2 ]; then
    echo "Expects exactly 2 arguments"
    echo "Usage: $0 <path to P4 program> <path to output dir>"
    exit 1
fi

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

python2 $THIS_DIR/gen_bmv2_config.py $1 \
  --out-bin $2/device_config.bin --out-p4info $2/p4info.proto.txt
