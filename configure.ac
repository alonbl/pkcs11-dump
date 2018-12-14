#
# Copyright (c) 2005-2008 Alon Bar-Lev <alon.barlev@gmail.com>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING.GPL included with this
# distribution); if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#

AC_PREREQ([2.60])

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [3])
define([PACKAGE_VERSION_FIX], [4])

AC_INIT([pkcs11-dump], [PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([pkcs11-dump.cpp])
AC_CONFIG_MACRO_DIR([m4])

PKCS11_DUMP_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
PKCS11_DUMP_VERSION_MINOR="PACKAGE_VERSION_MINOR"
PKCS11_DUMP_VERSION_FIX="PACKAGE_VERSION_FIX"

AC_CANONICAL_HOST

AC_ARG_WITH(
	[cygwin-native],
	[AC_HELP_STRING([--with-cygwin-native], [compile native win32])],
	,
	[with_cygwin_native="no"]
)

dnl Check for some target-specific stuff
test -z "${WIN32}" && WIN32="no"
test -z "${CYGWIN}" && CYGWIN="no"
case "${host}" in
	*-mingw32*|*-winnt*)
		WIN32="yes"
		CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
	;;
	*-cygwin*)
		AC_MSG_CHECKING([cygwin mode to use])
		CYGWIN="yes"
		if test "${with_cygwin_native}" = "yes"; then
			AC_MSG_RESULT([Using native win32])
			CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
			CFLAGS="${CFLAGS} -mno-cygwin"
			WIN32="yes"
		else
			AC_MSG_RESULT([Using cygwin])
			CPPFLAGS="${CPPFLAGS} -DCRYPTOKI_FORCE_WIN32"
			AC_DEFINE([USE_CYGWIN], [1], [Define if you are on Cygwin])
		fi
	;;
esac

AC_ARG_ENABLE(
	[pedantic],
	[AC_HELP_STRING([--enable-pedantic], [enable pedantic compile mode @<:@disabled@:>@])],
	,
	[enable_pedantic="no"]
)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG
dnl Add libtool support.
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
		LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)

if test "${WIN32}" = "yes"; then
	AC_ARG_VAR([MAN2HTML], [man2html utility])
	AC_CHECK_PROGS([MAN2HTML], [man2html])
	test -z "${MAN2HTML}" && AC_MSG_ERROR([man2html is required for win32])
fi
AC_FUNC_MKTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ \
	gettimeofday memmove memset socket strchr strdup strerror strrchr \
	snprintf \
])

# Checks for header files.
AC_HEADER_STDC
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_CHECK_HEADERS([[ \
	stdio.h \
	stdlib.h \
	stdargs.h \
	malloc.h \
	ctype.h \
	string.h \
	errno.h \
]])
AC_CHECK_HEADERS([ \
	signal.h \
	dlfcn.h \
	unistd.h \
])

if test "${WIN32}" != "yes"; then
	AC_CHECK_LIB([dl], [dlopen])

	PKG_CHECK_MODULES(
		[OPENSSL],
		[libcrypto >= 0.9.7],
		[have_openssl="yes"],
		[PKG_CHECK_MODULES(
			[OPENSSL],
			[openssl >= 0.9.7],
			[have_openssl="yes"],
			[AC_CHECK_LIB(
				[crypto],
				[RSA_version],
				[
					have_openssl="yes"
					OPENSSL_LIBS="-lcrypto"
				],
				[have_openssl="no"]
			)]
		)]
	)
	CXXFLAGS="${CXXFLAGS} ${OPENSSL_CFLAGS}"
	LIBS="${LIBS} ${OPENSSL_LIBS}"
fi

if test "${enable_pedantic}" = "yes"; then
	CXXFLAGS="${CXXFLAGS} -ansi -pedantic -D__STRICT_ANSI__ -D_ISOC99_SOURCE -D_BSD_SOURCE -D_POSIX_SOURCE"
	CXXFLAGS="${CXXFLAGS} -Wall -Wextra -Wpointer-arith -Wsign-compare -Wno-unused-parameter -Wno-unused-function"
fi

if test "${WIN32}" = "yes"; then
	LIBS="${LIBS} -lcrypt32"
fi

AC_SUBST([PKCS11_DUMP_VERSION_MAJOR])
AC_SUBST([PKCS11_DUMP_VERSION_MINOR])
AC_SUBST([PKCS11_DUMP_VERSION_FIX])

AM_CONDITIONAL(WIN32, test "${WIN32}" = "yes")
AM_CONDITIONAL(CYGWIN, test "${CYGWIN}" = "yes")
AC_OUTPUT([
	Makefile
	versioninfo.rc
])
