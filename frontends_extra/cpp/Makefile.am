ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/../../include

libpifecpp_la_SOURCES = \
src/tables.cpp

nobase_include_HEADERS = \
PI/frontends/cpp/tables.h

noinst_PROGRAMS = example
example_SOURCES = example.cpp
testdata_dirpath = $(top_srcdir)/../../examples/testdata
p4_name = p4
example_CPPFLAGS = \
-I$(top_srcdir)/../../include \
-DTESTDATADIR=\"$(testdata_dirpath)\"
fe_defines = pi_fe_defines_$(p4_name).h
gen_fe_defines = $(top_builddir)/../../generators/pi_gen_fe_defines
$(fe_defines) : $(testdata_dirpath)/simple_router.json $(gen_fe_defines)
	$(gen_fe_defines) -c $< -d $(abs_builddir) -n $(p4_name)
BUILT_SOURCES = $(fe_defines)

if WITH_BMV2
example_LDADD = \
$(top_builddir)/../../src/libpi.la \
libpifecpp.la \
$(top_builddir)/../../targets/bmv2/libpi_bmv2.la \
$(top_builddir)/../../src/libpip4info.la \
-lthrift -lruntimestubs -lsimpleswitch_thrift
else
example_LDADD = \
$(top_builddir)/../../src/libpi.la \
libpifecpp.la \
$(top_builddir)/../../src/libpip4info.la \
$(top_builddir)/../../targets/dummy/libpi_dummy.la
endif

lib_LTLIBRARIES = libpifecpp.la

CLEANFILES = $(fe_defines)
