ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/../include \
-I$(top_srcdir)/frontend \
-I$(top_builddir)/cpp_out \
-I$(top_srcdir)/p4info \
-I$(top_srcdir)/../third_party/googletest/googletest/include \
-I$(top_srcdir)/../third_party/googletest/googlemock/include \
-DTESTDATADIR=\"$(abs_top_srcdir)/../tests/testdata\"

TESTS = \
test_p4info_convert \
test_proto_fe \
test_proto_fe_packet_io

common_source = main.cpp

common_libs = \
$(top_builddir)/../third_party/libgmock.la \
$(top_builddir)/../third_party/libgtest.la \
$(PROTOBUF_LIBS)

test_p4info_convert_SOURCES = $(common_source) test_p4info_convert.cpp

test_p4info_convert_LDADD = \
$(top_builddir)/p4info/libpiconvertproto.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/../src/libpip4info.la \
$(common_libs)

proto_fe_common_source = $(common_source) mock_switch.h mock_switch.cpp

test_proto_fe_SOURCES = $(proto_fe_common_source) test_proto_fe.cpp
test_proto_fe_packet_io_SOURCES = $(proto_fe_common_source) \
test_proto_fe_packet_io.cpp

# this is an awful hack and a big time saver :)
# thanks to this, I do not need to implement all of the _pi_* functions, only
# the one I actually need for the tests. To me this is acceptable as I only use
# this for unit tests
test_proto_fe_LDFLAGS = $(LD_IGNORE_UNRESOLVED_SYMBOLS)
test_proto_fe_packet_io_LDFLAGS = $(LD_IGNORE_UNRESOLVED_SYMBOLS)

proto_fe_libs = \
$(top_builddir)/p4info/libpiconvertproto.la \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/../frontends_extra/cpp/libpifecpp.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/../src/libpiall.la \
$(top_builddir)/../src/libpip4info.la \
$(common_libs)

test_proto_fe_LDADD = $(proto_fe_libs)
test_proto_fe_packet_io_LDADD = $(proto_fe_libs)

check_PROGRAMS = \
test_p4info_convert \
test_proto_fe \
test_proto_fe_packet_io
