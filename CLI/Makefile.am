ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

noinst_LTLIBRARIES = libpicli.la

CPPFLAGS = -I$(top_srcdir)/inc

libpicli_la_LIBADD =

libpicli_la_SOURCES = \
commands.h \
table_add.c \
table_delete.c \
error_codes.h \
error_codes.c \
utils.h \
utils.c

bin_PROGRAMS = pi_CLI_dummy

common_source = \
main.c

LDADD = \
libpicli.la \
$(top_builddir)/src/libpi.la \
$(top_builddir)/src/frontends/generic/libpifegeneric.la \
$(top_builddir)/src/libpip4info.la

pi_CLI_dummy_LDADD = $(LDADD) \
$(top_builddir)/targets/dummy/libpi_dummy.la
pi_CLI_dummy_SOURCES = $(common_source)

# pi_CLI_bmv2_SOURCES = $(common_source)
