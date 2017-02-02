# DOXYGEN SUPPORT
@DX_RULES@

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

if WITH_CLI
MAYBE_CLI = CLI
endif

if WITH_PROTO
MAYBE_PROTO = proto
endif

# examples need to come after generators!
# proto depends on frontends_extra/cpp!
SUBDIRS = third_party lib include src generators targets $(MAYBE_CLI) examples \
bin tests frontends_extra $(MAYBE_PROTO)

DIST_SUBDIRS = third_party lib include src generators targets CLI examples \
bin tests frontends_extra $(MAYBE_PROTO)

AM_DISTCHECK_CONFIGURE_FLAGS = --with-bmv2 --with-fe-cpp

# ensure the distribution of the doxygen configuration file
EXTRA_DIST = $(top_srcdir)/docs/doxygen.cfg \
	     $(top_srcdir)/docs/bfn_latex.sty \
	     $(top_srcdir)/docs/*.md

mostlyclean-local:
	-$(RM) -r $(DX_CLEANFILES)
