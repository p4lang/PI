ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/../include \
-I$(top_srcdir)/frontend \
-I$(top_srcdir)/cpp_out \
-I$(top_srcdir)/p4info \
-I$(top_srcdir)/../third_party/googletest/googletest/include \
-I$(top_srcdir)/../third_party/googletest/googlemock/include \
-DTESTDATADIR=\"$(abs_top_srcdir)/../tests/testdata\"

TESTS = \
test_p4info_convert

common_source = main.cpp

test_p4info_convert_SOURCES = $(common_source) test_p4info_convert.cpp

LDADD = \
$(top_builddir)/p4info/libpiconvertproto.la \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/../frontends_extra/cpp/libpifecpp.la \
$(top_builddir)/libpiproto.la \
$(top_builddir)/../src/libpip4info.la \
$(top_builddir)/../third_party/libgmock.la \
$(top_builddir)/../third_party/libgtest.la \
$(PROTOBUF_LIBS)

check_PROGRAMS = \
test_p4info_convert
