ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

check_PROGRAMS = example
testdata_dirpath = $(top_srcdir)/../../examples/testdata
p4_name = p4
AM_CPPFLAGS = \
-I$(top_srcdir) \
-I$(top_srcdir)/../../include \
-I$(top_srcdir)/../../lib \
-DTESTDATADIR=\"$(testdata_dirpath)\"
fe_defines = pi_fe_defines_$(p4_name).h
gen_fe_defines = $(top_builddir)/../../generators/pi_gen_fe_defines
$(fe_defines) : $(testdata_dirpath)/simple_router.json $(gen_fe_defines)
	$(gen_fe_defines) -c $< -d $(abs_builddir) -n $(p4_name)
example_SOURCES = example.cpp
nodist_example_SOURCES = $(fe_defines)
# This is a bit risky. See "Recording Dependencies manually" at
# https://www.gnu.org/software/automake/manual/html_node/Built-Sources-Example.html#Built-Sources-Example
example.$(OBJEXT) : $(fe_defines)

if WITH_BMV2
LDADD = \
$(top_builddir)/../../src/libpi.la \
$(top_builddir)/libpifecpp.la \
$(top_builddir)/../../targets/bmv2/libpi_bmv2.la \
$(top_builddir)/../../src/libpip4info.la \
-lthrift -lruntimestubs -lsimpleswitch_thrift
else
LDADD = \
$(top_builddir)/../../src/libpi.la \
$(top_builddir)/libpifecpp.la \
$(top_builddir)/../../src/libpip4info.la \
$(top_builddir)/../../targets/dummy/libpi_dummy.la
endif

CLEANFILES = $(fe_defines)
