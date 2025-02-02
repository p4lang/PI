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

AM_CPPFLAGS = \
-I$(top_srcdir)/include \
-I$(top_srcdir)/lib

bin_PROGRAMS = pi_gen_fe_defines

pi_gen_fe_defines_SOURCES = fe_defines.c

pi_gen_fe_defines_LDADD = \
$(top_builddir)/src/libpip4info.la \
$(top_builddir)/src/libpiutils.la \
$(top_builddir)/lib/libpitoolkit.la
