ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

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
src/device_mgr.cpp \
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
src/statusor.h \
src/idle_timeout_buffer.h \
src/idle_timeout_buffer.cpp

libpifeproto_la_LIBADD = \
$(top_builddir)/../frontends_extra/cpp/libpifecpp.la \
$(top_builddir)/p4info/libpiconvertproto.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/third_party/libfmt.la \
$(BOOST_THREAD_LIB)

nobase_include_HEADERS = \
PI/frontends/proto/device_mgr.h \
PI/frontends/proto/logging.h

lib_LTLIBRARIES = libpifeproto.la
