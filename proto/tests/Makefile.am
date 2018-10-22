ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

# issytem for generated code, to avoid potential warnings
AM_CPPFLAGS = \
-I$(top_srcdir)/../include \
-I$(top_srcdir)/frontend \
-I$(top_srcdir)/third_party \
-isystem$(top_builddir)/cpp_out \
-isystem$(top_builddir)/grpc_out \
-I$(top_srcdir)/../frontends_extra/cpp \
-I$(top_srcdir) \
-I$(top_srcdir)/p4info \
-I$(top_srcdir)/server \
-I$(top_srcdir)/../third_party/googletest/googletest/include \
-I$(top_srcdir)/../third_party/googletest/googlemock/include \
-DTESTDATADIR=\"$(abs_top_srcdir)/../tests/testdata\"

if WITH_SYSREPO
AM_CPPFLAGS += -DWITH_SYSREPO
endif

TESTS = \
test_p4info_convert \
test_proto_fe \
test_proto_fe_digest \
test_proto_fe_packet_io \
test_proto_fe_set_pipeline_config \
test_server_no_pipeline_config \
test_server_gnmi \
test_server_arbitration \
test_pi_server \
test_task_queue

common_source = main.cpp

common_libs = \
$(top_builddir)/../third_party/libgmock.la \
$(top_builddir)/../third_party/libgtest.la

test_p4info_convert_SOURCES = $(common_source) test_p4info_convert.cpp

test_p4info_convert_LDADD = \
$(top_builddir)/p4info/libpiconvertproto.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/../src/libpip4info.la \
$(common_libs) \
$(PROTOBUF_LIBS)

proto_fe_common_source = $(common_source) \
mock_switch.h \
mock_switch.cpp \
matchers.h \
matchers.cpp

test_proto_fe_SOURCES = $(proto_fe_common_source) test_proto_fe.cpp
test_proto_fe_digest_SOURCES = $(proto_fe_common_source) \
test_proto_fe_digest.cpp
test_proto_fe_packet_io_SOURCES = $(proto_fe_common_source) \
test_proto_fe_packet_io.cpp
test_proto_fe_set_pipeline_config_SOURCES =$(proto_fe_common_source) \
test_proto_fe_set_pipeline_config.cpp

test_task_queue_SOURCES = $(proto_fe_common_source) test_task_queue.cpp

mock_switch_libs = \
$(top_builddir)/p4info/libpiconvertproto.la \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/../frontends_extra/cpp/libpifecpp.la \
$(top_builddir)/../src/libpiall.la \
$(top_builddir)/../src/libpip4info.la \
$(common_libs)

proto_fe_libs = \
$(mock_switch_libs) \
$(top_builddir)/libpiprotobuf.la \
$(PROTOBUF_LIBS)

test_proto_fe_LDADD = $(proto_fe_libs)
test_proto_fe_digest_LDADD = $(proto_fe_libs)
test_proto_fe_packet_io_LDADD = $(proto_fe_libs)
test_proto_fe_set_pipeline_config_LDADD = $(proto_fe_libs)

test_task_queue_LDADD = $(proto_fe_libs)

test_server_common_source = $(proto_fe_common_source) \
server/utils.h \
server/utils.cpp
test_server_libs = \
$(top_builddir)/server/libpigrpcserver.la \
$(mock_switch_libs) \
$(top_builddir)/libpiprotogrpc.la \
$(top_builddir)/libpiprotobuf.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS)

test_server_no_pipeline_config_SOURCES = $(test_server_common_source) \
server/test_no_pipeline_config.cpp
test_server_no_pipeline_config_LDADD = $(test_server_libs)

test_server_gnmi_SOURCES = $(test_server_common_source) \
server/test_gnmi.cpp
test_server_gnmi_LDADD = $(test_server_libs)

test_server_arbitration_SOURCES = $(test_server_common_source) \
server/test_arbitration.cpp
test_server_arbitration_LDADD = $(test_server_libs)

test_pi_server_SOURCES = $(test_server_common_source) \
server/test_pi_server.cpp
test_pi_server_LDADD = $(test_server_libs)

check_PROGRAMS = \
test_p4info_convert \
test_proto_fe \
test_proto_fe_digest \
test_proto_fe_packet_io \
test_proto_fe_set_pipeline_config \
test_server_no_pipeline_config \
test_server_gnmi \
test_server_arbitration \
test_pi_server \
test_task_queue
