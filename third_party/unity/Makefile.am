ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

noinst_LTLIBRARIES = libunity.la

libunity_la_SOURCES = \
src/unity.c \
src/unity_fixture.c \
include/unity/unity.h \
include/unity/unity_fixture.h \
include/unity/unity_fixture_internals.h \
include/unity/unity_fixture_malloc_overrides.h \
include/unity/unity_internals.h

AM_CPPFLAGS = -I$(srcdir)/include/unity
