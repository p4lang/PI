SUBDIRS = frontends

AM_CPPFLAGS += \
-I$(top_srcdir)/include \
-isystem$(top_srcdir)/third_party/cJSON/include

libpip4info_la_SOURCES = \
p4info/actions.c \
p4info/actions_int.h \
p4info/fields.c \
p4info/fields_int.h \
p4info/p4info_struct.h \
p4info/tables.c \
p4info/tables_int.h \
config_readers/bmv2_json_reader.c \
config_readers/readers.h \
p4info/p4info.c

libpip4info_la_LIBADD = \
$(top_builddir)/third_party/cJSON/libcjson.la \
libpiutils.la

libpi_la_SOURCES = \
pi.c \
pi_tables.c \
pi_value.c

libpiutils_la_SOURCES = \
utils/logging.h \
utils/utils.h \
utils/utils.c \
utils/serialize.c

libpi_la_LIBADD = \
libpip4info.la \
libpiutils.la

# order important because libpi requires libpip4info
lib_LTLIBRARIES = libpip4info.la libpi.la

noinst_LTLIBRARIES = libpiutils.la
