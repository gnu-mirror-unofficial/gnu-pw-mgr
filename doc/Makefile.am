
#  This file is part of gnu-pw-mgr.
#
#  Copyright (C) 2013 Bruce Korb - all rights reserved
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

INFO_DEPS       = gnu-pw-mgr.info
BUILT_SOURCES   = invoke-gnu-pw-mgr.texi gnu-pw-mgr.1
texi_sources    = fdl.texi intro.texi warnings.texi
EXTRA_DIST      = gnu-pw-mgr.texi $(texi_sources) $(BUILT_SOURCES)
TEXI2DVI_FLAGS  = --texinfo='@pagesizes 9.5in,7.0in'
info_TEXINFOS   = gnu-pw-mgr.texi
dist_man1_MANS  = gnu-pw-mgr.1

all : gnu-pw-mgr.1 invoke-gnu-pw-mgr.texi

gnu-pw-mgr.1 :
	@-test -x ../src/gnu-pw-mgr || \
	cd ../src ; \
	$(MAKE) gnu-pw-mgr
	autogen -MFxxx --help >/dev/null 2>&1 || exit 0 ; \
	PATH=`cd ../src && pwd`:$${PATH} ; set -x ; \
	autogen -MFdep-man -b gnu-pw-mgr -T agman-cmd.tpl ../src/opts.def

# The following is asinine, but the automake rules remove the file without
# any sort of explanation and I don't want to spend hours figuring out why
# I am wrong.  The bloody tool is wrong for doing it silently.  I've given
# enough hints to automake that it should keep its hands off.
#
gnu-pw-mgr.texi :
	cp -fp gnu-pw-mgr-doc.texi $@

invoke-gnu-pw-mgr.texi :
	@-test -x ../src/gnu-pw-mgr || \
	cd ../src ; \
	$(MAKE) gnu-pw-mgr
	@autogen -MFxxx --help >/dev/null 2>&1 || exit 0 ; \
	PATH=`cd ../src && pwd`:$${PATH} ; set -x ; \
	autogen -DLEVEL=chapter -MFdep-info -b gnu-pw-mgr -T agtexi-cmd.tpl \
		../src/opts.def
	@test -f gnu-pw-mgr.texi || cp -fp gnu-pw-mgr-doc.texi gnu-pw-mgr.texi
