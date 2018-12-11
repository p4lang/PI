ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

# Remove -Werror
AM_CXXFLAGS =

if WITH_PROTO_DEMO
MAYBE_PROTO_DEMO = demo_grpc
endif

SUBDIRS = . third_party p4info frontend server $(MAYBE_PROTO_DEMO) tests

PROTOFLAGS = -I$(abs_srcdir) -I$(abs_builddir)

# This makefile relies on the symbolic link that we create google ->
# googleapis/google. Without it, we run into some issues with `protoc`. An
# alternative would be to cd into googleapis when compiling the protos there; we
# will switch to that alternative if the need arises.

# Absolute paths are needed here for 'make distcheck' to work properly
protos = \
$(abs_srcdir)/p4/v1/p4data.proto \
$(abs_srcdir)/p4/v1/p4runtime.proto \
$(abs_srcdir)/p4/config/v1/p4info.proto \
$(abs_srcdir)/p4/config/v1/p4types.proto \
$(abs_srcdir)/google/rpc/status.proto \
$(abs_srcdir)/google/rpc/code.proto \
$(abs_srcdir)/p4/tmp/p4config.proto \
$(abs_srcdir)/gnmi/gnmi.proto

# Somehow, using an absolute path above prevents me from using EXTRA_DIST =
# $(protos)
EXTRA_DIST = \
p4/v1/p4data.proto \
p4/v1/p4runtime.proto \
p4/config/v1/p4info.proto \
p4/config/v1/p4types.proto \
google/rpc/status.proto \
google/rpc/code.proto \
p4/tmp/p4config.proto \
gnmi/gnmi.proto

proto_cpp_files = \
cpp_out/p4/v1/p4data.pb.cc \
cpp_out/p4/v1/p4data.pb.h \
cpp_out/p4/v1/p4runtime.pb.cc \
cpp_out/p4/v1/p4runtime.pb.h \
cpp_out/p4/config/v1/p4info.pb.cc \
cpp_out/p4/config/v1/p4info.pb.h \
cpp_out/p4/config/v1/p4types.pb.cc \
cpp_out/p4/config/v1/p4types.pb.h \
cpp_out/google/rpc/status.pb.cc \
cpp_out/google/rpc/status.pb.h \
cpp_out/google/rpc/code.pb.cc \
cpp_out/google/rpc/code.pb.h \
cpp_out/p4/tmp/p4config.pb.cc \
cpp_out/p4/tmp/p4config.pb.h \
cpp_out/gnmi/gnmi.pb.cc \
cpp_out/gnmi/gnmi.pb.h

proto_grpc_files = \
grpc_out/p4/v1/p4data.grpc.pb.cc \
grpc_out/p4/v1/p4data.grpc.pb.h \
grpc_out/p4/v1/p4runtime.grpc.pb.cc \
grpc_out/p4/v1/p4runtime.grpc.pb.h \
grpc_out/p4/config/v1/p4info.grpc.pb.cc \
grpc_out/p4/config/v1/p4info.grpc.pb.h \
grpc_out/p4/config/v1/p4types.grpc.pb.cc \
grpc_out/p4/config/v1/p4types.grpc.pb.h \
grpc_out/google/rpc/status.grpc.pb.cc \
grpc_out/google/rpc/status.grpc.pb.h \
grpc_out/google/rpc/code.grpc.pb.cc \
grpc_out/google/rpc/code.grpc.pb.h \
grpc_out/p4/tmp/p4config.grpc.pb.cc \
grpc_out/p4/tmp/p4config.grpc.pb.h \
grpc_out/gnmi/gnmi.grpc.pb.cc \
grpc_out/gnmi/gnmi.grpc.pb.h

includep4dir = $(includedir)/p4/v1/
nodist_includep4_HEADERS = \
cpp_out/p4/v1/p4data.pb.h \
grpc_out/p4/v1/p4data.grpc.pb.h \
cpp_out/p4/v1/p4runtime.pb.h \
grpc_out/p4/v1/p4runtime.grpc.pb.h

includep4configdir = $(includedir)/p4/config/v1/
nodist_includep4config_HEADERS = \
cpp_out/p4/config/v1/p4info.pb.h \
grpc_out/p4/config/v1/p4info.grpc.pb.h \
cpp_out/p4/config/v1/p4types.pb.h \
grpc_out/p4/config/v1/p4types.grpc.pb.h

includep4tmpdir = $(includedir)/p4/tmp/
nodist_includep4tmp_HEADERS = \
cpp_out/p4/tmp/p4config.pb.h \
grpc_out/p4/tmp/p4config.grpc.pb.h

includegoogledir = $(includedir)/google/rpc/
nodist_includegoogle_HEADERS = \
cpp_out/google/rpc/status.pb.h \
cpp_out/google/rpc/code.pb.h \
grpc_out/google/rpc/status.grpc.pb.h \
grpc_out/google/rpc/code.grpc.pb.h

includegnmidir = $(includedir)/gnmi/
nodist_includegnmi_HEADERS = \
cpp_out/gnmi/gnmi.pb.h \
grpc_out/gnmi/gnmi.grpc.pb.h

AM_CPPFLAGS = -Icpp_out -Igrpc_out \
-I$(top_srcdir)/../include \
-I$(top_srcdir)

BUILT_SOURCES = $(proto_cpp_files) $(proto_grpc_files)

if HAVE_GRPC_PY_PLUGIN
p4pydir = $(pythondir)/p4
nodist_p4py_PYTHON = \
py_out/p4/__init__.py

p4v1pydir = $(pythondir)/p4/v1
nodist_p4v1py_PYTHON = \
py_out/p4/v1/p4data_pb2.py \
py_out/p4/v1/p4runtime_pb2.py \
py_out/p4/v1/__init__.py

p4configpydir = $(pythondir)/p4/config
nodist_p4configpy_PYTHON = \
py_out/p4/config/__init__.py

p4configv1pydir = $(pythondir)/p4/config/v1
nodist_p4configv1py_PYTHON = \
py_out/p4/config/v1/p4info_pb2.py \
py_out/p4/config/v1/p4types_pb2.py \
py_out/p4/config/v1/__init__.py

# this one is temporary
p4tmppydir = $(pythondir)/p4/tmp
nodist_p4tmppy_PYTHON = \
py_out/p4/tmp/p4config_pb2.py \
py_out/p4/tmp/__init__.py

googlepydir = $(pythondir)/google
nodist_googlepy_PYTHON = \
py_out/google/__init__.py

googlerpcpydir = $(pythondir)/google/rpc
nodist_googlerpcpy_PYTHON = \
py_out/google/rpc/code_pb2.py \
py_out/google/rpc/status_pb2.py \
py_out/google/rpc/__init__.py

gnmipydir = $(pythondir)/gnmi
nodist_gnmipy_PYTHON = \
py_out/gnmi/__init__.py \
py_out/gnmi/gnmi_pb2.py

BUILT_SOURCES += \
$(nodist_p4py_PYTHON) \
$(nodist_p4v1py_PYTHON) \
$(nodist_p4configpy_PYTHON) \
$(nodist_p4configv1py_PYTHON) \
$(nodist_p4tmppy_PYTHON) \
$(nodist_googlepy_PYTHON) \
$(nodist_googlerpcpy_PYTHON) \
$(nodist_gnmipy_PYTHON)
endif

# See http://www.gnu.org/software/automake/manual/html_node/Multiple-Outputs.html

# Is there any issue with running protoc only once, instead of once per proto?
proto_files.ts: $(protos)
	@rm -f proto_files.tmp
	@touch proto_files.tmp
	@mkdir -p $(builddir)/cpp_out
	@mkdir -p $(builddir)/grpc_out
	$(PROTOC) $^ --cpp_out $(builddir)/cpp_out $(PROTOFLAGS)
	$(PROTOC) $^ --grpc_out $(builddir)/grpc_out --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $(PROTOFLAGS)
if HAVE_GRPC_PY_PLUGIN
	@mkdir -p $(builddir)/py_out
# With the Python plugin, it seems that I need to use a single command for proto
# + grpc and that the output directory needs to be the same (because the grpc
# plugin inserts code into the proto-generated files). But maybe I am just using
# an old version of the Python plugin.
	$(PROTOC) $^ --python_out $(builddir)/py_out $(PROTOFLAGS) --grpc_out $(builddir)/py_out --plugin=protoc-gen-grpc=$(GRPC_PY_PLUGIN)
	@touch $(builddir)/py_out/p4/__init__.py $(builddir)/py_out/p4/v1/__init__.py
	@touch $(builddir)/py_out/p4/config/__init__.py $(builddir)/py_out/p4/config/v1/__init__.py
	@touch $(builddir)/py_out/p4/tmp/__init__.py
	@touch $(builddir)/py_out/google/__init__.py $(builddir)/py_out/google/rpc/__init__.py $(builddir)/py_out/gnmi/__init__.py
endif
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

# libpiprotobuf = only protobuf files
# libpiprotogrpc = only grpc files
# It used to be that I had a library combining both (i.e. it was created by
# compiling and linking both proto_cpp_files and proto_grpc_files). Some
# executables ended up linking to both libraries which lead to an issue when
# compiling with clang in optimized mode similar to that one:
# https://github.com/tensorflow/tensorflow/issues/8394
lib_LTLIBRARIES = libpiprotobuf.la libpiprotogrpc.la

# generated source should not be distributed
nodist_libpiprotobuf_la_SOURCES = $(proto_cpp_files)
nodist_libpiprotogrpc_la_SOURCES = $(proto_grpc_files)

libpiprotobuf_la_SOURCES = src/util.cpp

libpiprotobuf_la_LIBADD = $(PROTOBUF_LIBS)
libpiprotogrpc_la_LIBADD = libpiprotobuf.la $(PROTOBUF_LIBS) $(GRPC_LIBS)

nobase_include_HEADERS = \
PI/proto/util.h

CLEANFILES = $(BUILT_SOURCES) proto_files.ts
