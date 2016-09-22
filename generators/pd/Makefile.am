ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

python_PYTHON = \
gen_pd.py \
tenjin_wrapper.py

# See
# http://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/Installation-Directory-Variables.html
edit = sed \
	-e 's|@pythondir[@]|$(pythondir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g'

pi_gen_pd: Makefile
	rm -f $@ $@.tmp
	$(edit) $(srcdir)/$@.in >$@.tmp
	chmod +x $@.tmp
	chmod a-w $@.tmp
	mv $@.tmp $@

pi_gen_pd: pi_gen_pd.in

bin_SCRIPTS = pi_gen_pd

EXTRA_DIST = pi_gen_pd.in

nobase_dist_pkgdata_DATA = \
templates/pd/pd.h \
templates/pd/pd_tables.h \
templates/pd/pd_types.h \
templates/pd/pd_counters.h \
templates/pd/pd_meters.h \
templates/src/pd.c \
templates/src/pd_tables.c \
templates/src/pd_counters.c \
templates/src/pd_meters.c \
templates/src/pd_utils.h \
templates/src/pd_utils.c \
templates/thrift/p4_pd_rpc.thrift \
templates/thrift-src/p4_pd_rpc_server.ipp \
templates/thrift-src/pd_rpc_server.cpp \
templates/thrift-src/pd_rpc_server.h

CLEANFILES = $(bin_SCRIPTS)
