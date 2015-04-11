#! /bin/sh

##  This file is part of Gnu-Pw-Mgr.
##
##  Gnu-Pw-Mgr Copyright (C) 1992-2014 by Bruce Korb - all rights reserved
##
##  Gnu-Pw-Mgr is free software: you can redistribute it and/or modify it
##  under the terms of the GNU General Public License as published by the
##  Free Software Foundation, either version 3 of the License, or
##  (at your option) any later version.
##
##  Gnu-Pw-Mgr is distributed in the hope that it will be useful, but
##  WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
##  See the GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License along
##  with this program.  If not, see <http://www.gnu.org/licenses/>.

typeset -r prog=$(basename "$0" .sh)
typeset -r progdir=$(\cd $(dirname "$0") && pwd -P)
typeset -r program=${progdir}/$(basename "$0")
typeset -r progpid=$$

builddir=`pwd`

die()
{
    exec 1> ${TMPDIR}/err-report.txt 2>&1
    echo "mk-agen-texi FAILED: $*"
    echo
    cat ${LOG_FILE}
    exec 2>&8 1>&2 8>&-
    cat ${TMPDIR}/err-report.txt
    trap : EXIT
    echo leaving ${TMPDIR} in place
    kill -TERM ${progpid}
    exit 1
}

set_config_values()
{
    PS4='>gpm-${FUNCNAME}> '
    TMPDIR=`pwd`/gpm-texi-$$.d
    rm -rf gpm-texi-*.d
    mkdir ${TMPDIR} || die "cannot make ${TMPDIR} directory"

    LOG_FILE=${TMPDIR}/texi.log
    exec 8>&2 2> ${LOG_FILE}

    nl='
'   ht='	'
    : ${MAKE=`command -v make`}
    : ${srcdir=`pwd`}
    unset CDPATH

    if ( : shopt -qo xtrace
         exec 2>/dev/null 1>&2
         shopt -qo xtrace
         exit $?
       )
    then
        trap "echo 'saved tmp dir:  ${TMPDIR}';chmod 777 ${TMPDIR}" EXIT
        VERBOSE=true
        dashx=-x
    else
        trap "rm -rf ${TMPDIR}" EXIT
        VERBOSE=false
        dashx=
    fi

    srcdir=`cd ${srcdir=\`pwd\`} ; pwd`
    proj_name=gnu-pw-mgr
    export MAKE LOG_FILE TMPDIR srcdir proj_name
}

build_gnudocs() {
    local gend=$(
        while :
        do
            gend=${top_srcdir}/build-aux/gendocs.sh
            test -f "$gend" && break
            gend=${top_builddir}/build-aux/gendocs.sh
            test -f "$gend" && break
            die "cannot find gendocs.sh"
        done
        cd `dirname "$gend"`
        echo `pwd`/gendocs.sh
    )

    local sedcmd='/^@author @email/ {
	s/.*{//
	s/}.*//
	s/@@*/@/g
	p
	q
    }'

    title=`sed -n 's/^@title  *//p' ${proj_name}.texi`
    email=--email' '`sed -n "$sedcmd" ${proj_name}.texi`
    opts="--texi2html ${email}"
    PS4='>${FUNCNAME:-gd}> ' ${SHELL} ${dashx} \
        ${gend} $opts gnu-pw-mgr "$title"
}

set_config_values
build_gnudocs

exit 0

## Local Variables:
## mode: shell-script
## indent-tabs-mode: nil
## sh-indentation: 4
## sh-basic-offset: 4
## End:
