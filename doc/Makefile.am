
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
SORT_SRC        = sort-pw-cfg.1 invoke-sort-pw-cfg.texi
PRJ_SRC         = invoke-$(PROJ_NAME).texi $(PROJ_NAME).1
INVOKE_SRC      = invoke-$(PROJ_NAME).texi invoke-sort-pw-cfg.texi
GEN_SOURCES     = $(PRJ_SRC) $(SORT_SRC)
DEP_FILES       = dep-invoke-$(PROJ_NAME).texi dep-invoke-sort-pw-cfg.texi \
	dep-$(PROJ_NAME).1 dep-sort-pw-cfg.1
texi_sources    = fdl.texi intro.texi warnings.texi
EXTRA_DIST      = $(PROJ_NAME).texi $(texi_sources) $(GEN_SOURCES)
TEXI2DVI_FLAGS  = --texinfo='@pagesizes 9.5in,7.0in'
info_TEXINFOS   = $(PROJ_NAME).texi
dist_man1_MANS  = $(PROJ_NAME).1 sort-pw-cfg.1

passenv         = MAKE=$(MAKE) srcdir="$(srcdir)" SHELL="$(POSIX_SHELL)" \
	top_builddir="$(top_builddir)" top_srcdir="$(top_srcdir)"

run_mkman       = $(passenv) $(POSIX_SHELL) $${dashx} mk-gnudoc.sh

check_exe   = test -x $(top_builddir)/src/$(1) || \
	{ cd $(top_builddir)/src ; $(MAKE) $(1) ; }
gen_invoke  = PATH="$(top_builddir)/src:$${PATH}" \
    autogen -DLEVEL=chapter -MF$@ -b $(1) -T agtexi-cmd.tpl \
	$(top_srcdir)/src/$(2) ; \
    test -f $@
gen_man     = autogen -MFdep-$@ -b $(1) -T agman-cmd.tpl \
	$(top_srcdir)/src/$(2) ; \
    test -f $@

all : $(DEP_FILES)

-include dep-$(PROJ_NAME).1
$(PROJ_NAME).1 : dep-$(PROJ_NAME).1
dep-$(PROJ_NAME).1 :
	$(call gen_man,$(PROJ_NAME),opts.def)

-include dep-sort-pw-cfg.1
sort-pw-cfg.1 : dep-sort-pw-cfg.1
dep-sort-pw-cfg.1 :
	$(call gen_man,sort-pw-cfg,sort-opts.def)

-include dep-invoke-$(PROJ_NAME).texi
invoke-$(PROJ_NAME).texi : dep-invoke-$(PROJ_NAME).texi
dep-invoke-$(PROJ_NAME).texi :
	$(call check_exe,$(PROJ_NAME) )
	$(call gen_invoke,$(PROJ_NAME),opts.def )

-include dep-invoke-sort-pw-cfg.texi
invoke-sort-pw-cfg.texi : dep-invoke-sort-pw-cfg.texi
dep-invoke-sort-pw-cfg.texi :
	$(call check_exe,sort-pw-cfg )
	$(call gen_invoke,sort-pw-cfg,sort-opts.def )

clean-local :
	rm -f dep-* invoke-*.texi invoke-*.menu *.1

gnudocs : $(INVOKE_SRC) $(srcdir)/gendocs_template
	$(run_mkman) $@

.NOTPARALLEL:

# doc/Makefile.am ends here
