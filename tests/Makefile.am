AM_CPPFLAGS += \
-I$(top_srcdir)/inc \
-DTESTDATADIR=\"$(abs_srcdir)/testdata\"

TESTS = test_temp

test_temp_SOURCES = temp.c

# libpi needs to come before libpi_dummy, because it uses it
LDADD = \
$(top_builddir)/src/libpi.la \
$(top_builddir)/targets/dummy/libpi_dummy.la

check_PROGRAMS = test_temp
