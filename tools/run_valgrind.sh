#!/bin/bash

# Copyright 2013-present Barefoot Networks, Inc.
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

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_DIR=$THIS_DIR/../tests

cd $TEST_DIR

libtool --mode=execute valgrind --leak-check=full --show-reachable=yes ./test_all
return_status=$?

cd -

exit $return_status
