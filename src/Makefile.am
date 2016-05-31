SUBDIRS = frontends

AM_CPPFLAGS += \
-I$(top_srcdir)/inc \
-isystem$(top_srcdir)/third_party/cJSON/include

libpip4info_la_SOURCES = \
p4info/actions.c \
p4info/actions_int.h \
p4info/fields.c \
p4info/p4info_struct.h \
p4info/tables.c \
p4info/tables_int.h

libpi_la_SOURCES = \
pi.c \
pi_int.h \
pi_tables.c \
pi_value.c \
target/pi_imp.h \
target/pi_tables_imp.h

libpiutils_la_SOURCES = \
utils/utils.h \
utils/utils.c \
utils/serialize.h \
utils/serialize.c

libpireaders_la_SOURCES = \
config_readers/bmv2_json_reader.c \
config_readers/readers.h

libpireaders_la_LIBADD = \
$(top_srcdir)/third_party/cJSON/libcjson.la

libpi_la_LIBADD = \
libpip4info.la \
libpireaders.la \
libpiutils.la

lib_LTLIBRARIES = libpi.la libpip4info.la

noinst_LTLIBRARIES = libpiutils.la libpireaders.la
