#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([PI-bmv2], [0.1], [antonin@barefootnetworks.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_CXX
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

AC_LANG_PUSH(C)
AC_LANG_PUSH(C++)

AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])

# To simplify usage, we will update PATH, CPPFLAGS,.. to include the 'prefix'
# ones
adl_RECURSIVE_EVAL([$bindir], [BIN_DIR])
adl_RECURSIVE_EVAL([$includedir], [INCLUDE_DIR])
adl_RECURSIVE_EVAL([$libdir], [LIB_DIR])

CPPFLAGS="$CPPFLAGS -I$INCLUDE_DIR"
AC_CHECK_HEADER([bm/Standard.h], [],
  [AC_MSG_ERROR([bmv2 Thrift headers not found])])

AC_PATH_PROG([THRIFT], [thrift], [])
AC_CHECK_HEADER([thrift/Thrift.h], [], [AC_MSG_ERROR([Thrift headers not found. Install Thrift from http://thrift.apache.org/docs/install/])])

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T

AC_SUBST([AM_CPPFLAGS], ["-I$INCLUDE_DIR"])
AC_SUBST([AM_LDFLAGS], ["-L$LIB_DIR"])
AC_SUBST([AM_CXXFLAGS], ["-Wall -Werror -Wextra"])

# Generate makefiles
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
