AM_CPPFLAGS += \
-I$(top_srcdir)/include \
-I$(top_srcdir)/lib \
-isystem$(top_srcdir)/third_party/cJSON/include

# TODO(antonin): act_prof should be in a different directory (externs)
libpip4info_la_SOURCES = \
p4info/actions.c \
p4info/actions_int.h \
p4info/p4info_struct.h \
p4info/p4info_struct.c \
p4info/tables.c \
p4info/tables_int.h \
p4info/act_profs.c \
p4info/act_profs_int.h \
p4info/counters.c \
p4info/counters_int.h \
p4info/meters.c \
p4info/meters_int.h \
p4info/digests.c \
p4info/digests_int.h \
config_readers/bmv2_json_reader.c \
config_readers/native_json_reader.c \
config_readers/readers.h \
p4info/p4info.c \
p4info/p4info_name_map.h \
p4info/p4info_name_map.c \
p4info/p4info_common.h \
p4info/p4info_common.c \
p4info_int.h \
p4info/fast_id_vector.h \
p4info/fast_id_vector.c

libpip4info_la_LIBADD = \
$(top_builddir)/third_party/cJSON/libpicjson.la \
$(top_builddir)/lib/libpitoolkit.la \
libpiutils.la

libpi_la_SOURCES = \
pi.c \
pi_tables.c \
pi_act_prof.c \
pi_counter.c \
pi_meter.c \
pi_learn.c \
pi_value.c \
pi_mc.c \
pi_clone.c \
device_map.c \
device_map.h \
cb_mgr.c \
cb_mgr.h \
pi_tables_int.h \
pi_learn_int.h

if WITH_INTERNAL_RPC
libpi_la_SOURCES += \
pi_rpc_server.c \
pi_notifications_pub.h \
pi_notifications_pub.c
endif

libpi_la_LIBADD = \
libpip4info.la \
libpiutils.la \
$(top_builddir)/lib/libpitoolkit.la

libpiutils_la_SOURCES = \
utils/logging.h \
utils/logging.c \
utils/utils.h \
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
$(top_builddir)/lib/libpitoolkit.la

# order important because libpi requires libpip4info
lib_LTLIBRARIES = libpip4info.la libpi.la libpifegeneric.la libpiall.la

noinst_LTLIBRARIES = libpiutils.la
