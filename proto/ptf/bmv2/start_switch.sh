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

if [[ $EUID -ne 0 ]]; then
    echo "This script should be run using sudo or as the root user"
    exit 1
fi
simple_switch_grpc -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 \
    -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 \
    --log-console --no-p4 \
    -- --grpc-server-addr 0.0.0.0:9559
