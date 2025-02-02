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

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir) \
-I$(top_srcdir)/frontend \
-isystem $(top_builddir)/cpp_out \
-isystem $(top_builddir)/grpc_out

if WITH_SYSREPO
AM_CPPFLAGS += -DWITH_SYSREPO
endif

AM_CXXFLAGS = -Wall -Werror

lib_LTLIBRARIES = libpigrpcserver.la

libpigrpcserver_la_SOURCES = \
gnmi.h \
gnmi_dummy.cpp \
log.h \
pi_server.cpp \
shared_mutex.h \
uint128.h \
uint128.cpp \
pi_server_testing.h

if WITH_SYSREPO
libpigrpcserver_la_SOURCES += \
gnmi_sysrepo.cpp
endif

nobase_include_HEADERS = PI/proto/pi_server.h

libpigrpcserver_la_LIBADD = \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/libpiprotogrpc.la \
$(top_builddir)/libpiprotobuf.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS) \
$(BOOST_THREAD_LIB) $(BOOST_SYSTEM_LIB)
# causes issue with libpiproto as it includes a version of google.rpc.Status
# -lgrpc++_error_details
