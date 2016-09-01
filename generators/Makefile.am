ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = . pd

AM_CPPFLAGS = \
-I$(top_srcdir)/include \
-I$(top_srcdir)/lib

bin_PROGRAMS = pi_gen_fe_defines

pi_gen_fe_defines_SOURCES = fe_defines.c

pi_gen_fe_defines_LDADD = \
$(top_builddir)/src/libpip4info.la \
$(top_builddir)/src/libpiutils.la \
$(top_builddir)/lib/libpitoolkit.la
