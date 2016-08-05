AM_CPPFLAGS += \
-I$(top_srcdir)/include \
-isystem$(top_srcdir)/third_party/cJSON/include

# TODO(antonin): act_prof should be in a different directory (externs)
libpip4info_la_SOURCES = \
p4info/actions.c \
p4info/actions_int.h \
p4info/fields.c \
p4info/fields_int.h \
p4info/p4info_struct.h \
p4info/tables.c \
p4info/tables_int.h \
p4info/act_profs.c \
p4info/act_profs_int.h \
config_readers/bmv2_json_reader.c \
config_readers/native_json_reader.c \
config_readers/readers.h \
p4info/p4info.c

libpip4info_la_LIBADD = \
$(top_builddir)/third_party/cJSON/libpicjson.la \
libpiutils.la

libpi_la_SOURCES = \
pi.c \
pi_tables.c \
pi_act_prof.c \
pi_value.c \
pi_rpc_server.c

libpi_la_LIBADD = \
libpip4info.la \
libpiutils.la \
-lnanomsg

libpiutils_la_SOURCES = \
utils/logging.h \
utils/logging.c \
utils/utils.h \
utils/utils.c \
utils/serialize.c

libpifegeneric_la_SOURCES = \
frontends/generic/pi.c

libpiall_la_SOURCES = \
$(libpip4info_la_SOURCES) \
$(libpi_la_SOURCES) \
$(libpifegeneric_la_SOURCES)

libpiall_la_LIBADD = \
$(top_builddir)/third_party/cJSON/libpicjson.la \
libpiutils.la \
-lnanomsg

# order important because libpi requires libpip4info
lib_LTLIBRARIES = libpip4info.la libpi.la libpifegeneric.la libpiall.la

noinst_LTLIBRARIES = libpiutils.la
