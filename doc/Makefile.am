
#  This file is part of gnu-pw-mgr.
#
#  Copyright (C) 2013-2015 Bruce Korb - all rights reserved
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

DEP_FILES       =
MAN_PAGES       =
TEXI_DOC        =
MENU_FILES      =
GEN_SOURCES     = $(MAN_PAGES) $(TEXI_DOC)
texi_sources    = fdl.texi intro.texi warnings.texi
dist_man1_MANS  = $(MAN_PAGES)
info_TEXINFOS   = gnu-pw-mgr.texi
EXTRA_DIST      = $(info_TEXINFOS) $(texi_sources) $(GEN_SOURCES)
TEXI2DVI_FLAGS  = --texinfo='@pagesizes 9.5in,7.0in'

passenv     = MAKE=$(MAKE) srcdir="$(srcdir)" SHELL="$(POSIX_SHELL)" \
	top_builddir="$(top_builddir)" top_srcdir="$(top_srcdir)"

run_mkman   = $(passenv) $(POSIX_SHELL) $${dashx} mk-gnudoc.sh

check_exe   = test -x $(top_builddir)/src/$(1) || \
	{ cd $(top_builddir)/src ; $(MAKE) $(1) ; }

gen_invoke  = PATH="$(top_builddir)/src:$${PATH}" \
    autogen -DLEVEL=chapter -MF$@ -b $(1) -T agtexi-cmd.tpl \
	$(top_srcdir)/src/$(2) ; \
    test -f $@

gen_man     = autogen -MF$@ -b $(1) -T agman-cmd.tpl \
	$(top_srcdir)/src/$(2) ; \
    test -f $@

all : $(DEP_FILES)

clean-local :
	rm -f $(DEP_FILES) $(GEN_SOURCES) $(MENU_FILES)

gnudocs : $(TEXI_DOC) $(srcdir)/gendocs_template
	$(run_mkman) $@

# # # # #  gnu-pw-mgr.1   # # # # #
#
DEP_FILES += dep-gnu-pw-mgr.1
MAN_PAGES += gnu-pw-mgr.1
-include dep-gnu-pw-mgr.1
dep-gnu-pw-mgr.1 :
	$(call gen_man,gnu-pw-mgr,opts.def)
gnu-pw-mgr.1 : dep-gnu-pw-mgr.1

# # # # #  sort-pw-cfg.1   # # # # #
#
MAN_PAGES += sort-pw-cfg.1
DEP_FILES += dep-sort-pw-cfg.1
-include dep-sort-pw-cfg.1
dep-sort-pw-cfg.1 :
	$(call gen_man,sort-pw-cfg,sort-opts.def)
sort-pw-cfg.1 : dep-sort-pw-cfg.1

# # # # #  invoke-gnu-pw-mgr.texi   # # # # #
#
DEP_FILES += dep-invoke-gnu-pw-mgr.texi
TEXI_DOC  += invoke-gnu-pw-mgr.texi
MENU_FILES+= invoke-gnu-pw-mgr.menu
-include dep-invoke-gnu-pw-mgr.texi
dep-invoke-gnu-pw-mgr.texi :
	$(call check_exe,gnu-pw-mgr )
	$(call gen_invoke,gnu-pw-mgr,opts.def )
invoke-gnu-pw-mgr.texi : dep-invoke-gnu-pw-mgr.texi

# # # # #  invoke-sort-pw-cfg.texi   # # # # #
#
DEP_FILES += dep-invoke-sort-pw-cfg.texi
TEXI_DOC  += invoke-sort-pw-cfg.texi
MENU_FILES+= invoke-sort-pw-cfg.menu
-include dep-invoke-sort-pw-cfg.texi
dep-invoke-sort-pw-cfg.texi :
	$(call check_exe,sort-pw-cfg )
	$(call gen_invoke,sort-pw-cfg,sort-opts.def )
invoke-sort-pw-cfg.texi : dep-invoke-sort-pw-cfg.texi

# # # # #
#
.NOTPARALLEL:
#
# doc/Makefile.am ends here
