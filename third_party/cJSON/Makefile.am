ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

noinst_LTLIBRARIES = libcjson.la

libcjson_la_SOURCES = src/cJSON.c include/cJSON/cJSON.h

libcjson_la_LIBADD = -lm

AM_CPPFLAGS = -I$(srcdir)/include/cJSON
