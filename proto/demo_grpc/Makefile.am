ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/../include \
-I$(top_srcdir)/frontend \
-I$(top_srcdir)/server \
-I$(top_builddir)/cpp_out \
-I$(top_builddir)/grpc_out \
-I$(top_srcdir)/p4info

AM_CXXFLAGS = -Wall -Werror

noinst_PROGRAMS = controller pi_server_dummy test_perf

pi_server_dummy_SOURCES = pi_server_main.cpp gnmi_mgr_dummy.cpp

test_perf_SOURCES = test_perf.cpp

controller_SOURCES = \
simple_router_mgr.cpp \
simple_router_mgr.h \
web_server.cpp \
web_server.h \
app.cpp

COMMON_SERVER_LIBS = \
$(top_builddir)/server/libpigrpcserver.la \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/libpiprotogrpc.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/../src/libpiall.la

if WITH_BMV2
bin_PROGRAMS = pi_grpc_server

pi_grpc_server_SOURCES = pi_server_main.cpp gnmi_mgr_dummy.cpp

pi_grpc_server_LDADD = \
$(COMMON_SERVER_LIBS) \
$(top_builddir)/../targets/bmv2/libpi_bmv2.la \
-lthrift -lruntimestubs -lsimpleswitch_thrift
endif  # WITH_BMV2

pi_server_dummy_LDADD = \
$(COMMON_SERVER_LIBS) \
$(top_builddir)/../targets/dummy/libpi_dummy.la

test_perf_LDADD = \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/libpiprotogrpc.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/p4info/libpiconvertproto.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)

controller_LDADD = \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/libpiprotogrpc.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/p4info/libpiconvertproto.la \
-lmicrohttpd -lboost_system \
$(PROTOBUF_LIBS) $(GRPC_LIBS)
