# Copyright 2016 Barefoot Networks, Inc.
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

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS += \
-I$(top_srcdir)/include

bin_PROGRAMS = pi_gen_native_json

pi_gen_native_json_SOURCES = gen_pi_json.c

pi_gen_native_json_LDADD = \
$(top_builddir)/src/libpip4info.la

# This is the rpc server for bmv2
if WITH_BMV2
if WITH_INTERNAL_RPC
bin_PROGRAMS += pi_rpc_server

pi_rpc_server_SOURCES = rpc_server.c

pi_rpc_server_LDADD = \
$(top_builddir)/src/libpi.la \
$(top_builddir)/src/libpip4info.la \
$(top_builddir)/targets/bmv2/libpi_bmv2.la \
-lthrift -lruntimestubs -lsimpleswitch_thrift

# Dummy C++ source to cause C++ linking.
nodist_EXTRA_pi_rpc_server_SOURCES = dummy.cxx
endif
endif
