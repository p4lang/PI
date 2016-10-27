ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

PROTOFLAGS = -I.

proto = p4info.proto

EXTRA_DIST = $(proto)

proto_cpp_files = \
cpp_out/p4info.pb.cc \
cpp_out/p4info.pb.h

AM_CPPFLAGS = -Icpp_out

BUILT_SOURCES = $(proto_cpp_files)

# See http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html

proto_files.ts: $(proto)
	@rm -f proto_files.tmp
	@touch proto_files.tmp
	@mkdir -p $(builddir)/cpp_out
	$(PROTOC) $^ --cpp_out $(builddir)/cpp_out $(PROTOFLAGS)
	@mv -f proto_files.tmp $@

$(BUILT_SOURCES): proto_files.ts
## Recover from the removal of $@
	@if test -f $@; then :; else \
	  trap 'rm -rf proto_files.lock proto_files.ts' 1 2 13 15; \
## mkdir is a portable test-and-set
	if mkdir proto_files.lock 2>/dev/null; then \
## This code is being executed by the first process.
	  rm -f proto_files.ts; \
	  $(MAKE) $(AM_MAKEFLAGS) proto_files.ts; \
	  result=$$?; rm -rf proto_files.lock; exit $$result; \
	else \
## This code is being executed by the follower processes.
## Wait until the first process is done.
	  while test -d proto_files.lock; do sleep 1; done; \
## Succeed if and only if the first process succeeded.
	    test -f proto_files.ts; \
	  fi; \
	fi

noinst_LTLIBRARIES = libpip4infoproto.la

# generated source should not be distributed
nodist_libpip4infoproto_la_SOURCES = $(proto_cpp_files)

libpip4infoproto_la_LIBADD = $(PROTOBUF_LIBS)

bin_PROGRAMS = pi_gen_p4info_proto

pi_gen_p4info_proto_SOURCES = gen_p4info_proto.cpp

pi_gen_p4info_proto_LDADD = \
libpip4infoproto.la \
$(top_builddir)/../src/libpip4info.la

CLEANFILES = $(BUILT_SOURCES) proto_files.ts
