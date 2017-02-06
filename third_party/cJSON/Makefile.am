ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

lib_LTLIBRARIES = libpicjson.la

libpicjson_la_SOURCES = src/cJSON.c include/cJSON/cJSON.h

libpicjson_la_LIBADD = -lm

AM_CPPFLAGS = -I$(srcdir)/include/cJSON
AM_CFLAGS =
