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
config_readers/bmv2_json_reader.c \
config_readers/readers.h \
target/pi_imp.h \
target/pi_tables_imp.h

libpi_la_LIBADD = \
$(top_srcdir)/third_party/cJSON/libcjson.la \
libpip4info.la

lib_LTLIBRARIES = libpi.la libpip4info.la
