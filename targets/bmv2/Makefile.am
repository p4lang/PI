# a little hacky: the headers are in the parent of the configure subdir
AM_CPPFLAGS += \
-I$(top_srcdir)/../../include

libpi_bmv2_la_SOURCES = \
pi_imp.cpp \
pi_tables_imp.cpp \
pi_act_prof_imp.cpp \
pi_counter_imp.cpp \
pi_meter_imp.cpp \
pi_learn_imp.cpp \
conn_mgr.h \
conn_mgr.cpp \
common.h \
action_helpers.h \
action_helpers.cpp \
direct_res_spec.h \
direct_res_spec.cpp

libpi_bmv2_la_LIBADD = \
$(top_builddir)/../../src/libpip4info.la \
-lbmp4apps

noinst_LTLIBRARIES = libpi_bmv2.la
