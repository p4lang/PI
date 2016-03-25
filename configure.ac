#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([PI], [0.1], [antonin@barefootnetworks.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_CC_C99
# AC_PROG_CC_STDC
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# Checks for header files.
AC_LANG_PUSH(C)

AC_CHECK_HEADERS([stdlib.h string.h assert.h stdio.h stdint.h stdbool.h\
                  stddef.h time.h],
                 [], [AC_MSG_ERROR([Missing header file])])

AC_CHECK_FUNCS([malloc free strcmp strncmp strcpy strncpy strdup calloc \
                sprintf snprintf printf])
AC_CHECK_FUNCS([fopen fseek fread fputs])
AC_CHECK_FUNCS([rand srand time atoi])

# Check for libjudy
AC_CHECK_LIB([Judy], [Judy1Next], [], [AC_MSG_ERROR([Missing libJudy])])

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T

AC_SUBST([AM_CPPFLAGS], ["-DPI_LOG_ON"])
AC_SUBST([AM_CFLAGS], ["-Wall -Werror -Wextra"])

# Generate makefiles
AC_CONFIG_FILES([Makefile
                 inc/Makefile
                 src/Makefile
                 targets/Makefile
                 targets/dummy/Makefile
                 tests/Makefile
                 third_party/Makefile
                 third_party/cJSON/Makefile
                 third_party/unity/Makefile])

AC_OUTPUT
