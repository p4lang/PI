ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/include \
-I$(top_srcdir)/src  # for utils

bin_PROGRAMS = gen_fe_defines

gen_fe_defines_SOURCES = fe_defines.c

gen_fe_defines_LDADD = \
$(top_builddir)/src/libpip4info.la \
$(top_builddir)/src/libpiutils.la
