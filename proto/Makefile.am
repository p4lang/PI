ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

PROTOFLAGS = -I.

# This makefile relies on the symbolic link that we create google ->
# googleapis/google. Without it, we run into some issues with `protoc`. An
# alternative would be to cd into googleapis when compiling the protos there; we
# will switch to that alternative if the need arises.

protos = \
$(srcdir)/pi.proto \
$(srcdir)/google/rpc/status.proto \
$(srcdir)/google/rpc/code.proto \
$(srcdir)/device.proto \
$(srcdir)/resource.proto

EXTRA_DIST = $(protos)

proto_cpp_files = \
cpp_out/pi.pb.cc \
cpp_out/pi.pb.h \
cpp_out/google/rpc/status.pb.cc \
cpp_out/google/rpc/status.pb.h \
cpp_out/google/rpc/code.pb.cc \
cpp_out/google/rpc/code.pb.h \
cpp_out/device.pb.cc \
cpp_out/device.pb.h \
cpp_out/resource.pb.cc \
cpp_out/resource.pb.h

proto_grpc_files = \
grpc_out/pi.grpc.pb.cc \
grpc_out/pi.grpc.pb.h \
grpc_out/google/rpc/status.grpc.pb.cc \
grpc_out/google/rpc/status.grpc.pb.h \
grpc_out/google/rpc/code.grpc.pb.cc \
grpc_out/google/rpc/code.grpc.pb.h \
grpc_out/device.grpc.pb.cc \
grpc_out/device.grpc.pb.h \
grpc_out/resource.grpc.pb.cc \
grpc_out/resource.grpc.pb.h

AM_CPPFLAGS = -Icpp_out -Igrpc_out

BUILT_SOURCES = $(proto_cpp_files) $(proto_grpc_files)

# See http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html

# Is there any issue with running protoc only once, instead of once per proto?
proto_files.ts: $(protos)
	@rm -f proto_files.tmp
	@touch proto_files.tmp
	@mkdir -p $(builddir)/cpp_out
	@mkdir -p $(builddir)/grpc_out
	$(PROTOC) $^ --cpp_out $(builddir)/cpp_out $(PROTOFLAGS)
	$(PROTOC) $^ --grpc_out $(builddir)/grpc_out --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $(PROTOFLAGS)
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

# very likely to change in the future; for now the goal is just to have a
# skeleton makefile which compiles the generated source files.
noinst_LTLIBRARIES = libpiproto.la

# generated source should not be distributed
nodist_libpiproto_la_SOURCES = \
$(proto_cpp_files) $(proto_grpc_files)

libpiproto_la_LIBADD = $(PROTOBUF_LIBS) $(GRPC_LIBS)

CLEANFILES = $(BUILT_SOURCES) proto_files.ts
