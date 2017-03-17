ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/frontend \
-I$(top_builddir)/cpp_out \
-I$(top_builddir)/grpc_out

AM_CXXFLAGS = -Wall -Werror

lib_LTLIBRARIES = libpigrpcserver.la

libpigrpcserver_la_SOURCES = pi_server.cpp

nobase_include_HEADERS = PI/proto/pi_server.h

libpigrpcserver_la_LIBADD = \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/libpiproto.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)
