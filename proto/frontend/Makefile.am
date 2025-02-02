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

# for deprecated Protobuf fields
AM_CXXFLAGS += -Wno-error=deprecated-declarations

# include path for protoc-generated code will change when we agree on an
# installation path
AM_CPPFLAGS = \
-I$(top_srcdir)/../include \
-I$(top_builddir)/cpp_out \
-I$(top_srcdir)/../frontends_extra/cpp \
-I$(top_srcdir) \
-I$(top_srcdir)/p4info \
-I$(top_srcdir)/third_party

libpifeproto_la_SOURCES = \
src/bimap.h \
src/device_mgr.cpp \
src/access_arbitration.h \
src/access_arbitration.cpp \
src/action_prof_mgr.h \
src/action_prof_mgr.cpp \
src/table_info_store.h \
src/table_info_store.cpp \
src/action_helpers.h \
src/action_helpers.cpp \
src/match_key_helpers.h \
src/match_key_helpers.cpp \
src/packet_io_mgr.h \
src/packet_io_mgr.cpp \
src/common.h \
src/common.cpp \
src/logger.h \
src/logging.cpp \
src/report_error.h \
src/pre_mc_mgr.h \
src/pre_mc_mgr.cpp \
src/pre_clone_mgr.h \
src/pre_clone_mgr.cpp \
src/task_queue.h \
src/digest_mgr.h \
src/digest_mgr.cpp \
src/status_macros.h \
src/statusor.h \
src/idle_timeout_buffer.h \
src/idle_timeout_buffer.cpp \
src/watch_port_enforcer.h \
src/watch_port_enforcer.cpp

libpifeproto_la_LIBADD = \
$(top_builddir)/../frontends_extra/cpp/libpifecpp.la \
$(top_builddir)/p4info/libpiconvertproto.la \
$(top_builddir)/libserverconfig.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/third_party/libfmt.la \
$(BOOST_THREAD_LIB)

nobase_include_HEADERS = \
PI/frontends/proto/device_mgr.h \
PI/frontends/proto/logging.h

lib_LTLIBRARIES = libpifeproto.la
