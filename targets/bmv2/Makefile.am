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

# a little hacky: the headers are in the parent of the configure subdir
AM_CPPFLAGS += \
-I$(top_srcdir)/../../include

if WITH_PCAP_FIX
AM_CPPFLAGS += -DWITH_PCAP_FIX
endif

libpi_bmv2_la_SOURCES = \
pi-bmv2-config.h \
pi_imp.cpp \
pi_tables_imp.cpp \
pi_act_prof_imp.cpp \
pi_counter_imp.cpp \
pi_meter_imp.cpp \
pi_learn_imp.cpp \
pi_mc_imp.cpp \
pi_clone_imp.cpp \
conn_mgr.h \
conn_mgr.cpp \
common.h \
common.cpp \
action_helpers.h \
action_helpers.cpp \
direct_res_spec.h \
direct_res_spec.cpp \
cpu_send_recv.h \
cpu_send_recv.cpp

libpi_bmv2_la_LIBADD = \
$(top_builddir)/../../src/libpip4info.la \
-lbmp4apps

lib_LTLIBRARIES = libpi_bmv2.la

distclean-local: distclean-ax-prefix-config-h
distclean-ax-prefix-config-h:
	rm -f pi-bmv2-config.h
