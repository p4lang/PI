ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = . example

AM_CPPFLAGS = \
-I$(top_srcdir)/../../include

libpifecpp_la_SOURCES = \
src/tables.cpp

nobase_include_HEADERS = \
PI/frontends/cpp/tables.h

lib_LTLIBRARIES = libpifecpp.la
