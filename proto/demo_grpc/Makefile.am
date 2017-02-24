ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/../include \
-I$(top_srcdir)/frontend \
-I$(top_builddir)/cpp_out \
-I$(top_builddir)/grpc_out \
-I$(top_srcdir)/p4info

AM_CXXFLAGS = -Wall -Werror

bin_PROGRAMS = pi_grpc_server
noinst_PROGRAMS = test_client controller pi_server_dummy test_perf

pi_grpc_server_SOURCES = pi_server_main.cpp

pi_server_dummy_SOURCES = pi_server_main.cpp

test_client_SOURCES = test_client.cpp

test_perf_SOURCES = test_perf.cpp

controller_SOURCES = \
simple_router_mgr.cpp \
simple_router_mgr.h \
web_server.cpp \
web_server.h \
app.cpp

lib_LTLIBRARIES = libpigrpcserver.la

libpigrpcserver_la_SOURCES = pi_server.cpp

nobase_include_HEADERS = PI/proto/pi_server.h

COMMON_SERVER_LIBS = \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/../frontends_extra/cpp/libpifecpp.la \
$(top_builddir)/libpiproto.la \
$(top_builddir)/../src/libpiall.la \
$(top_builddir)/p4info/libpiconvertproto.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)

libpigrpcserver_la_LIBADD = \
$(COMMON_SERVER_LIBS)

# COMMON_SERVER_LIBS need to be repeated here for some reason, this seems to be
# specific to the libtool version packaged with Ubuntu (see
# http://stackoverflow.com/questions/11802727/libtool-doesnt-provide-library-dependencies-to-link). Also
# COMMON_SERVER_LIBS need to appear before libpigrpcserver, which I also don't
# explain.
pi_grpc_server_LDADD = \
$(COMMON_SERVER_LIBS) \
libpigrpcserver.la \
$(top_builddir)/../targets/bmv2/libpi_bmv2.la \
-lthrift -lruntimestubs -lsimpleswitch_thrift

pi_server_dummy_LDADD = \
$(COMMON_SERVER_LIBS) \
libpigrpcserver.la \
$(top_builddir)/../targets/dummy/libpi_dummy.la

test_client_LDADD = \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/libpiproto.la \
$(top_builddir)/p4info/libpiconvertproto.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)

test_perf_LDADD = \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/libpiproto.la \
$(top_builddir)/p4info/libpiconvertproto.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)

controller_LDADD = \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/libpiproto.la \
$(top_builddir)/p4info/libpiconvertproto.la \
-lmicrohttpd -lboost_system \
$(PROTOBUF_LIBS) $(GRPC_LIBS)
