ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

lib_LTLIBRARIES = libpicli.la

CPPFLAGS = -I$(top_srcdir)/include

libpicli_la_SOURCES = \
commands.h \
add_p4.c \
counter_commands.c \
device_commands.c \
meter_commands.c \
table_add.c \
table_delete.c \
table_dump.c \
table_modify.c \
table_set_default.c \
error_codes.h \
error_codes.c \
utils.h \
utils.c \
table_common.h \
table_common.c \
p4_config_repo.h \
p4_config_repo.c \
main.c

libpicli_la_SOURCES += \
act_profs/table_indirect_create_member.c \
act_profs/table_indirect_common.h \
act_profs/table_indirect_common.c

bin_PROGRAMS = pi_CLI_dummy pi_CLI_rpc

common_libs = \
libpicli.la \
$(top_builddir)/src/libpi.la \
$(top_builddir)/src/libpifegeneric.la \
$(top_builddir)/src/libpip4info.la \
-lnanomsg

pi_CLI_dummy_LDADD = $(common_libs) \
$(top_builddir)/targets/dummy/libpi_dummy.la
pi_CLI_dummy_SOURCES =

pi_CLI_rpc_LDADD = $(common_libs) \
$(top_builddir)/targets/rpc/libpi_rpc.la
pi_CLI_rpc_SOURCES =

if WITH_BMV2
bin_PROGRAMS += pi_CLI_bmv2
# TODO(antonin) the bm libs should probably have better names...
pi_CLI_bmv2_LDADD = $(common_libs) \
$(top_builddir)/targets/bmv2/libpi_bmv2.la \
-lthrift -lruntimestubs -lsimpleswitch_thrift
pi_CLI_bmv2_SOURCES =
# Dummy C++ source to cause C++ linking.
nodist_EXTRA_pi_CLI_bmv2_SOURCES = dummy.cxx
endif
