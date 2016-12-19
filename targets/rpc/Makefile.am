# a little hacky: the headers are in the parent of the configure subdir
AM_CPPFLAGS += \
-I$(top_srcdir)/include

libpi_rpc_la_SOURCES = \
pi_rpc.h \
pi_rpc.c \
pi_imp.c \
pi_tables_imp.c \
pi_act_prof_imp.c \
pi_counter_imp.c \
pi_meter_imp.c \
pi_learn_imp.c \
notifications.c

libpi_rpc_la_LIBADD = \
$(top_builddir)/src/libpip4info.la

lib_LTLIBRARIES = libpi_rpc.la
