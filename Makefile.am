ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

# examples need to come after generators!
SUBDIRS = third_party lib include src generators targets CLI examples bin \
tests frontends_extra

AM_DISTCHECK_CONFIGURE_FLAGS = --with-bmv2 --with-fe-cpp
