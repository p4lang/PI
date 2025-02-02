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
-I$(top_srcdir)/lib \
-DTESTDATADIR=\"$(abs_srcdir)/testdata\"

# TODO(antonin): find a way to remove libpip4info as a dep here (should come
# with libpi)
LDADD = \
$(top_builddir)/src/libpi.la \
$(top_builddir)/src/libpifegeneric.la \
$(top_builddir)/src/libpip4info.la \
$(top_builddir)/targets/dummy/libpi_dummy.la

check_PROGRAMS = example_1 example_2

example_1_SOURCES = example_1.c

# for example_2
p4_name = router

fe_defines = pi_fe_defines_$(p4_name).h

gen_fe_defines = $(top_builddir)/generators/pi_gen_fe_defines

$(fe_defines) : $(srcdir)/testdata/simple_router.json $(gen_fe_defines)
	$(gen_fe_defines) -c $< -d $(abs_builddir) -n $(p4_name)

example_2_SOURCES = example_2.c
nodist_example_2_SOURCES = $(fe_defines)
# This is a bit risky. See "Recording Dependencies manually" at
# https://www.gnu.org/software/automake/manual/html_node/Built-Sources-Example.html#Built-Sources-Example
example_2.$(OBJEXT) : $(fe_defines)

EXTRA_DIST = \
testdata/simple_router.json

CLEANFILES = $(fe_defines)
