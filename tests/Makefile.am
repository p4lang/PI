AM_CPPFLAGS += \
-I$(top_srcdir)/inc \
-I$(top_srcdir)/src \
-I$(top_srcdir)/third_party/unity/include \
-DTESTDATADIR=\"$(abs_srcdir)/testdata\"

TESTS = \
test_bmv2_json_reader \
test_p4info

common_source = main.c

test_bmv2_json_reader_SOURCES = $(common_source) test_bmv2_json_reader.c
test_bmv2_json_reader_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_BMV2_JSON_READER

test_p4info_SOURCES = $(common_source) test_p4info.c
test_p4info_CPPFLAGS = $(AM_CPPFLAGS) -DTEST_P4INFO

test_all_SOURCES = $(common_source) \
test_bmv2_json_reader.c \
test_p4info.c
test_all_CPPFLAGS = $(AM_CPPFLAGS) \
-DTEST_BMV2_JSON_READER \
-DTEST_P4INFO

# libpi needs to come before libpi_dummy, because it uses it
LDADD = \
$(top_builddir)/src/libpi.la \
$(top_builddir)/targets/dummy/libpi_dummy.la \
$(top_builddir)/third_party/unity/libunity.la

check_PROGRAMS = \
test_bmv2_json_reader \
test_p4info \
test_all
