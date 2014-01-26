
#  This file is part of gnu-pw-mgr.
#
#  Copyright (C) 2013-2014 Bruce Korb - all rights reserved
#
#  gnu-pw-mgr is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by the
#  Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  gnu-pw-mgr is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#  See the GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program.  If not, see <http://www.gnu.org/licenses/>.

PROJ_NAME       = gnu-pw-mgr
INFO_DEPS       = $(PROJ_NAME).info
BUILT_SOURCES   = invoke-$(PROJ_NAME).texi $(PROJ_NAME).1
texi_sources    = fdl.texi intro.texi warnings.texi
EXTRA_DIST      = $(PROJ_NAME).texi $(texi_sources) $(BUILT_SOURCES)
TEXI2DVI_FLAGS  = --texinfo='@pagesizes 9.5in,7.0in'
info_TEXINFOS   = $(PROJ_NAME).texi
dist_man1_MANS  = $(PROJ_NAME).1
passenv         = MAKE=$(MAKE) srcdir="$(srcdir)" SHELL="$(POSIX_SHELL)" \
	top_builddir="$(top_builddir)" top_srcdir="$(top_srcdir)"

run_mkman       = $(passenv) $(POSIX_SHELL) $${dashx} mk-gnudoc.sh

all : $(PROJ_NAME).1 invoke-$(PROJ_NAME).texi

$(PROJ_NAME).1 :
	@-test -x ../src/$(PROJ_NAME) || \
	cd ../src ; \
	$(MAKE) $(PROJ_NAME)
	autogen -MFxxx --help >/dev/null 2>&1 || exit 0 ; \
	PATH=`cd ../src && pwd`:$${PATH} ; set -x ; \
	autogen -MFdep-man -b $(PROJ_NAME) -T agman-cmd.tpl ../src/opts.def

# The following is asinine, but the automake rules remove the file without
# any sort of explanation and I don't want to spend hours figuring out why
# I am wrong.  The bloody tool is wrong for doing it silently.  I've given
# enough hints to automake that it should keep its hands off.
#
$(PROJ_NAME).texi :
	cp -fp $(PROJ_NAME)-doc.texi $@

invoke-$(PROJ_NAME).texi :
	@-test -x ../src/$(PROJ_NAME) || \
	cd ../src ; \
	$(MAKE) $(PROJ_NAME)
	@autogen -MFxxx --help >/dev/null 2>&1 || exit 0 ; \
	PATH=`cd ../src && pwd`:$${PATH} ; set -x ; \
	autogen -DLEVEL=chapter -MFdep-info -b $(PROJ_NAME) \
		-T agtexi-cmd.tpl ../src/opts.def
	@test -f $(PROJ_NAME).texi || \
		cp -fp $(PROJ_NAME)-doc.texi $(PROJ_NAME).texi

gnudocs             : $(srcdir)/gendocs_template invoke-$(PROJ_NAME).texi
	$(run_mkman) $@

.NOTPARALLEL:

# doc/Makefile.am ends here
