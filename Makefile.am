# Copyright 2016 Barefoot Networks, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Antonin Bas (antonin@barefootnetworks.com)

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
