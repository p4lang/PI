ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS += \
-I$(top_srcdir)/include

bin_PROGRAMS = rpc_server

rpc_server_SOURCES = rpc_server.c

rpc_server_LDADD = \
$(top_builddir)/src/libpi.la \
$(top_builddir)/src/libpip4info.la \
$(top_builddir)/targets/bmv2/libpi_bmv2.la \
-lnanomsg \
-lthrift -lruntimestubs -lsimpleswitch_thrift

# Dummy C++ source to cause C++ linking.
nodist_EXTRA_rpc_server_SOURCES = dummy.cxx
