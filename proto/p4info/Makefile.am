ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_CPPFLAGS = \
-I$(top_srcdir)/../include \
-I$(top_srcdir)/../src \
-I$(top_builddir)/cpp_out

bin_PROGRAMS = pi_convert_p4info

# convenience library to convert back-and-forth between p4info and the P4Info
# protobuf message
lib_LTLIBRARIES = libpiconvertproto.la

libpiconvertproto_la_SOURCES = \
p4info_to_and_from_proto.cpp

nobase_include_HEADERS = PI/proto/p4info_to_and_from_proto.h

libpiconvertproto_la_LIBADD = \
$(top_builddir)/libpiprotobuf.la \
$(PROTOBUF_LIBS)

pi_convert_p4info_SOURCES = \
convert_p4info.cpp

pi_convert_p4info_LDADD = \
$(builddir)/libpiconvertproto.la \
$(top_builddir)/libpiprotobuf.la \
$(top_builddir)/../src/libpip4info.la \
$(PROTOBUF_LIBS)
