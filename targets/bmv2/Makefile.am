# a little hacky: the headers are in the parent of the configure subdir
AM_CPPFLAGS += \
-I$(top_srcdir)/../../inc \
-I$(top_srcdir)/../../src

libpi_bmv2_la_SOURCES = \
pi_imp.cpp \
pi_tables_imp.cpp \
conn_mgr.h \
conn_mgr.cpp \
common.h

noinst_LTLIBRARIES = libpi_bmv2.la
