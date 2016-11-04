ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

if WITH_CLI
MAYBE_CLI = CLI
endif

if WITH_PROTO
MAYBE_PROTO = proto
endif

# examples need to come after generators!
SUBDIRS = third_party lib include src generators targets $(MAYBE_CLI) examples \
bin tests $(MAYBE_PROTO) frontends_extra

DIST_SUBDIRS = third_party lib include src generators targets CLI examples \
bin tests $(MAYBE_PROTO) frontends_extra

AM_DISTCHECK_CONFIGURE_FLAGS = --with-bmv2 --with-fe-cpp
