#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([bm_sim], [0.1], [antonin@barefootnetworks.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# Checks for header files.
AC_LANG_PUSH(C)

AC_CHECK_HEADERS([stdlib.h string.h assert.h stdio.h stdint.h],
                 [], [AC_MSG_ERROR([Missing header file])])

# Check for libjudy
AC_CHECK_LIB([Judy], [Judy1Next], [], [AC_MSG_ERROR([Missing libJudy])])

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Generate makefiles
AC_CONFIG_FILES([Makefile
                 inc/Makefile
                 src/Makefile
                 targets/Makefile
                 targets/dummy/Makefile
                 tests/Makefile])

AC_OUTPUT
