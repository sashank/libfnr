# -*- Autoconf -*-
#
# Copyright (c) 2014 Cisco Systems, Inc.
#

AC_PREREQ([2.59])
AC_INIT([fnr], [1.0.0], [libfnr-dev@external.cisco.com])
AM_INIT_AUTOMAKE(fnr, 1.0.0)
AC_CONFIG_SRCDIR([src/fnr.c])
AC_CONFIG_HEADERS([config.h])

m4_include([config/check_ssl.m4])

# Checks for programs.
:${CFLAGS=""}
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_CC_C_O

# Checks for libraries.
AC_MSG_CHECKING(for libssl)
with_ssl=no
AC_ARG_WITH(libssl, AC_HELP_STRING(--with-libssl=DIR,use libssl in DIR),
[ case "$withval" in
  no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT(yes)
     with_ssl=$withval
     if test "x$enable_win32" = "xyes"; then	
     	CFLAGS="$CFLAGS -I$with_ssl/include"
     	CXXFLAGS="$CXXFLAGS -I$with_ssl/include"
     	LIBS="$LIBS -L$with_ssl/lib/MinGW"
	LIBS_END="$LIBS_END -leay32"
     else
	CFLAGS="$CFLAGS -I$with_ssl/include"
        AC_CHECK_LIB(dl, dlopen, [LIBDL=-ldl])
     	CXXFLAGS="$CXXFLAGS -I$with_ssl/include"
	LIBS="$LIBS -L$with_ssl/lib -lssl -lcrypto $LIBDL"
     fi
     ;;
  esac ]
)

if test "x$with_ssl" = "xno"; then
   CHECK_SSL
fi

# Checks for header files.
AC_CHECK_HEADERS([string.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 test/Makefile])

AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug], [enable debugging, default: no]),
[case "${enableval}" in
             yes) debug=true ;;
             no)  debug=false ;;
             *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac], [debug=false])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

AC_OUTPUT
