# -*- Mode: Makefile -*-
#  This file is part of gnu-pw-mgr.
#
#  Copyright (C) 2013-2018 Bruce Korb - all rights reserved
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

GNULIB_LD              = $(GETHOSTNAME_LIB) $(LIBSOCKET) $(LIB_CRYPTO) $(LTLIBINTL)
LOCAL_LD               = $(top_builddir)/libopts/libopts.la \
	$(top_builddir)/lib/libgnu.la $(GNULIB_LD)

bin_PROGRAMS 	       = gnu-pw-mgr sort-pw-cfg
gnu_pw_mgr_SOURCES     = gnu-pw-mgr.c
gnu_pw_mgr_CPPFLAGS    = $(incs)
gnu_pw_mgr_LDADD       = $(LOCAL_LD)

sort_pw_cfg_SOURCES    = sort-pw-cfg.c
sort_pw_cfg_CPPFLAGS   = $(incs)
sort_pw_cfg_LDADD      = $(LOCAL_LD)

lib_incs     	= -I$(top_srcdir)/lib -I$(top_srcdir)/src -I$(top_builddir)/lib
ao_incs      	= -I$(top_srcdir)/libopts -I$(top_builddir)/libopts
incs            = $(lib_incs) $(ao_incs)

xtra_src        = cclass.c cfg-file.c domains.c fix-pw.c pw-opts.c scribble.c \
		seed.c wrap-libnettle.c fwd.h sort-fwd.h
opts_src     	= opts.c opts.h
opt_src      	= set-opt.c set-opt.h
sort_opts_src   = sort-opts.c sort-opts.h
str_src         = gpw-str.c gpw-str.h
gen_src      	= $(opts_src) $(opt_src) $(sort_opts_src) $(str_src)
EXTRA_DIST   	= $(gen_src) opts.def sort-opts.def gpw-str.def $(xtra_src)
