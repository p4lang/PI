ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/frontend \
-I$(top_builddir)/cpp_out \
-I$(top_builddir)/grpc_out

AM_CXXFLAGS = -Wall -Werror

lib_LTLIBRARIES = libpigrpcserver.la

libpigrpcserver_la_SOURCES = \
pi_server.cpp \
uint128.h \
uint128.cpp

nobase_include_HEADERS = PI/proto/pi_server.h

libpigrpcserver_la_LIBADD = \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/libpiprotogrpc.la \
$(top_builddir)/libpiprotobuf.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)
# causes issue with libpiproto as it includes a version of google.rpc.Status
# -lgrpc++_error_details
