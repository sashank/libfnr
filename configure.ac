# -*- Autoconf -*-
#
# Copyright (c) 2014 Cisco Systems, Inc.
#

AC_PREREQ([2.59])
AC_INIT([fnr], [1.0.0], [libfnr-dev@external.cisco.com])
AM_INIT_AUTOMAKE([1.11 dist-bzip2 foreign -Wall -Werror])
AC_CONFIG_SRCDIR([src/fnr.c])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
:${CFLAGS=""}
AC_PROG_CC
AM_PROG_CC_C_O

# This did not exist pre AM 1.11.x (where x is somewhere >0 and <3),
# but it is necessary in AM 1.12.x.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# SSL options
AC_ARG_WITH([libssl], AC_HELP_STRING([--with-libssl=DIR], [use libssl in DIR]),
            [], [with_libssl=yes])
AS_CASE([$with_libssl],
    [yes], [],
    [no],  [AC_MSG_NOTICE([libfnr requires libssl -- specifying --without-libssl is disallowed])
            AC_MSG_ERROR([Cannot continue])],
    [AS_IF([test ! -d "$with_libssl"],
           [AC_MSG_NOTICE([Supplied SSL directory $with_libssl does not exist])
            AC_MSG_ERROR([Cannot continue])])
     AS_IF([test ! -d "$with_libssl/include"],
           [AC_MSG_NOTICE([Supplied SSL directory $with_libssl/include does not exist])
            AC_MSG_ERROR([Cannot continue])])
     CPPFLAGS="$CPPFLAGS -I$with_libssl/include"
     CXXCPPFLAGS="$CXXCPPFLAGS -I$with_libssl/include"

     AS_IF([test -d "$with_libssl/lib"], [LDFLAGS="-L$with_libssl/lib"],
         [AS_IF([test -d "$with_libssl/lib64"],
              [LDFLAGS="-L$with_libssl/lib64"],
              [AC_MSG_NOTICE([Cannot find $with_libssl/lib or $with_libssl/lib64])
               AC_MSG_ERROR([Cannot continute])])
         ])
    ])

# Checks for header files.
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADER([openssl/aes.h], [],
    [AC_MSG_NOTICE([Cannot find openssl/aes.h])
     AC_MSG_ERROR([Cannot continue])])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])
AC_CHECK_LIB([crypto], [AES_set_encrypt_key], [],
    [AC_MSG_NOTICE([Cannot find libcrypto])
     AC_MSG_ERROR([Cannot continue])])
AC_CHECK_LIB([ssl], [SSL_set_msg_callback], [],
    [AC_MSG_NOTICE([Cannot find libssl])
     AC_MSG_ERROR([Cannot continue])])

LT_INIT

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

