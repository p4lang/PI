#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([PI-fe-cpp], [0.1], [antonin@barefootnetworks.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_CXX
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

AC_LANG_PUSH(C)
AC_LANG_PUSH(C++)

AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])

want_bmv2=no
AC_ARG_WITH([bmv2],
    AS_HELP_STRING([--with-bmv2], [Build for bmv2 target]),
    [want_bmv2=yes], [])

AM_CONDITIONAL([WITH_BMV2], [test "$want_bmv2" = yes])

AC_ARG_ENABLE([Werror],
    AS_HELP_STRING([--enable-Werror], [Make all compiler warnings fatal]),
    [enable_Werror="$enableval"], [enable_Werror=no])

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T

# check for pthreads
AX_PTHREAD([], [AC_MSG_ERROR([Missing pthread library])])

EXTRA_CXXFLAGS="-Wall -Wextra"
AS_IF([test "$enable_Werror" = "yes"], [EXTRA_CXXFLAGS="$EXTRA_CXXFLAGS -Werror"])
AC_SUBST([AM_CXXFLAGS], ["$PTHREAD_CFLAGS $EXTRA_CXXFLAGS"])

# Generate makefiles
AC_CONFIG_FILES([Makefile
                 example/Makefile])

AC_OUTPUT
