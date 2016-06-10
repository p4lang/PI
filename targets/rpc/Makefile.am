# a little hacky: the headers are in the parent of the configure subdir
AM_CPPFLAGS += \
-I$(top_srcdir)/include

libpi_rpc_la_SOURCES = \
pi_rpc.c

libpi_rpc_la_LIBADD = \
$(top_builddir)/src/libpip4info.la \
-lnanomsg

noinst_LTLIBRARIES = libpi_rpc.la
