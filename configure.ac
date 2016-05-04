dnl
dnl  This file is part of gnu-pw-mgr.
dnl
dnl  Copyright (C) 2013-2016 Bruce Korb - all rights reserved
dnl
dnl  gnu-pw-mgr is free software: you can redistribute it and/or modify it
dnl  under the terms of the GNU General Public License as published by the
dnl  Free Software Foundation, either version 3 of the License, or
dnl  (at your option) any later version.
dnl
dnl  gnu-pw-mgr is distributed in the hope that it will be useful, but
dnl  WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
dnl  See the GNU General Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License along
dnl  with this program.  If not, see <http://www.gnu.org/licenses/>.
dnl
AC_INIT([gnu-pw-mgr],
    m4_esyscmd([cat .tarball-version]),
    [bkorb@gnu.org], gnu-pw-mgr)

AS_BOX([Configuring AC_PACKAGE_TARNAME AC_PACKAGE_VERSION])
AC_USE_SYSTEM_EXTENSIONS

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([gnu check-news 1.13 dist-xz])

AC_PROG_CC_C99

gl_EARLY
gl_INIT
LT_INIT

m4_pushdef([AO_Libopts_Dir],[libopts])dnl
LIBOPTS_BUILD_BLOCKED=''
LIBOPTS_CHECK_COMMON([libopts])
INVOKE_LIBOPTS_MACROS
m4_popdef([AO_Libopts_Dir])
[test "X${GCC}" = Xyes && \
    CFLAGS=`echo $CFLAGS -Wcast-align -Wmissing-prototypes \
	-Wpointer-arith -Wshadow -Wstrict-prototypes -Wwrite-strings \
	-Wno-format-contains-nul -fno-strict-aliasing -Wstrict-aliasing=2`]
gl_GC_RANDOM
AH_TOP([
#ifndef GNU_PW_MGR_CONFIG_H_GUARD
#define GNU_PW_MGR_CONFIG_H_GUARD 1])

AH_BOTTOM([
#ifndef NUL
# define NUL '\0'
#endif

#ifndef NL
# define NL '\n'
#endif

#ifndef NBBY
# define NBBY 8 /* Number of Bits per BYte */
#endif

#endif // GNU_PW_MGR_CONFIG_H_GUARD])
AC_CHECK_FUNCS_ONCE([tcgetattr tcsetattr getpwuid])
AC_CONFIG_FILES([Makefile doc/Makefile lib/Makefile src/Makefile tests/Makefile])
AC_CONFIG_FILES([libopts/Makefile])
AM_CONDITIONAL([AG_MF],[$ag_cv_ag_supports_mf])
AM_PROG_CC_C_O

AC_OUTPUT
