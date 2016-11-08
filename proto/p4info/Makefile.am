ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

bin_PROGRAMS = pi_gen_p4info_proto

pi_gen_p4info_proto_SOURCES = gen_p4info_proto.cpp

pi_gen_p4info_proto_LDADD = \
$(top_builddir)/libpiproto.la \
$(top_builddir)/../src/libpip4info.la
