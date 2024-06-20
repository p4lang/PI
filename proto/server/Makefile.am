ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir) \
-I$(top_srcdir)/frontend \
-isystem $(top_builddir)/cpp_out \
-isystem $(top_builddir)/grpc_out

if WITH_SYSREPO
AM_CPPFLAGS += -DWITH_SYSREPO
endif

AM_CXXFLAGS = -Wall -Werror -Wno-deprecated-declarations

lib_LTLIBRARIES = libpigrpcserver.la

libpigrpcserver_la_SOURCES = \
gnmi.h \
gnmi_dummy.cpp \
log.h \
pi_server.cpp \
shared_mutex.h \
uint128.h \
uint128.cpp \
pi_server_testing.h

if WITH_SYSREPO
libpigrpcserver_la_SOURCES += \
gnmi_sysrepo.cpp
endif

nobase_include_HEADERS = PI/proto/pi_server.h

libpigrpcserver_la_LIBADD = \
$(top_builddir)/frontend/libpifeproto.la \
$(top_builddir)/libpiprotogrpc.la \
$(top_builddir)/libpiprotobuf.la \
$(PROTOBUF_LIBS) $(GRPC_LIBS) \
$(BOOST_THREAD_LIB) $(BOOST_SYSTEM_LIB)
# causes issue with libpiproto as it includes a version of google.rpc.Status
# -lgrpc++_error_details
