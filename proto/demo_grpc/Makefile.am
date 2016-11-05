ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/../include \
-I$(top_srcdir)/frontend \
-I$(top_builddir)/cpp_out \
-I$(top_builddir)/grpc_out

AM_CXXFLAGS = -Wall -Werror

bin_PROGRAMS = pi_server test_client controller pi_server_dummy test_perf

pi_server_SOURCES = pi_server.cpp

pi_server_dummy_SOURCES = pi_server.cpp

test_client_SOURCES = test_client.cpp

test_perf_SOURCES = test_perf.cpp

controller_SOURCES = \
simple_router_mgr.cpp \
simple_router_mgr.h \
web_server.cpp \
web_server.h \
app.cpp

pi_server_LDADD = \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/../frontends_extra/cpp/libpi_fecpp.la \
$(top_builddir)/libpiproto.la \
$(top_builddir)/../src/libpiall.la \
$(top_builddir)/../targets/bmv2/libpi_bmv2.la \
-lthrift -lruntimestubs -lsimpleswitch_thrift \
$(PROTOBUF_LIBS) $(GRPC_LIBS)

pi_server_dummy_LDADD = \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/../frontends_extra/cpp/libpi_fecpp.la \
$(top_builddir)/libpiproto.la \
$(top_builddir)/../src/libpiall.la \
$(top_builddir)/../targets/dummy/libpi_dummy.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)

test_client_LDADD = \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/libpiproto.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)

test_perf_LDADD = \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/libpiproto.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)

controller_LDADD = \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/libpiproto.la \
-lmicrohttpd -lboost_system \
$(PROTOBUF_LIBS) $(GRPC_LIBS)
