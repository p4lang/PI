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
-I$(top_srcdir)/../include \
-I$(top_srcdir)/../src \
-I$(top_builddir)/cpp_out

bin_PROGRAMS = pi_convert_p4info

# convenience library to convert back-and-forth between p4info and the P4Info
# protobuf message
lib_LTLIBRARIES = libpiconvertproto.la

libpiconvertproto_la_SOURCES = \
p4info_to_and_from_proto.cpp

nobase_include_HEADERS = PI/proto/p4info_to_and_from_proto.h

libpiconvertproto_la_LIBADD = \
$(top_builddir)/libpiprotobuf.la \
$(PROTOBUF_LIBS)

pi_convert_p4info_SOURCES = \
convert_p4info.cpp

pi_convert_p4info_LDADD = \
$(builddir)/libpiconvertproto.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/../src/libpip4info.la \
$(PROTOBUF_LIBS)
