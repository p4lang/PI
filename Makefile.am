ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

# examples need to come after generators!
SUBDIRS = third_party include src generators targets CLI examples tests \
frontends_extra bin

AM_DISTCHECK_CONFIGURE_FLAGS = --with-bmv2 --with-fe-cpp
