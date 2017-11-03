#!/usr/bin/env bash
if [[ $EUID -ne 0 ]]; then
    echo "This script should be run using sudo or as the root user"
    exit 1
fi
simple_switch_grpc -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 \
    -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 \
    --log-console --no-p4 \
    -- --grpc-server-addr 0.0.0.0:50051
