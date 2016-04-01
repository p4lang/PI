#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([PI], [0.1], [antonin@barefootnetworks.com])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_CC_C99
# AC_PROG_CC_STDC

# did not want to have this, but needed to link the CLI for bmv2
# cannot be executed conditionally
# it will not cause configure to error though if no g++ compiler is detected (so
# long as --with-bmv2 is not specified of course)
AC_PROG_CXX

want_bmv2=no
AC_ARG_WITH([bmv2],
    AS_HELP_STRING([--with-bmv2], [Build for bmv2 target]),
    [want_bmv2=yes], [])

AM_CONDITIONAL([WITH_BMV2], [test "$want_bmv2" = yes])

LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# Checks for header files.
AC_LANG_PUSH(C)

# To simplify usage, we will update PATH, CPPFLAGS,.. to include the 'prefix'
# ones
adl_RECURSIVE_EVAL([$bindir], [BIN_DIR])
adl_RECURSIVE_EVAL([$includedir], [INCLUDE_DIR])
adl_RECURSIVE_EVAL([$libdir], [LIB_DIR])

AC_CHECK_HEADERS([stdlib.h string.h assert.h stdio.h stdint.h stdbool.h\
                  stddef.h time.h ctype.h unistd.h arpa/inet.h\
                  sys/types.h sys/stat.h inttypes.h],
                 [], [AC_MSG_ERROR([Missing header file])])

AC_CHECK_FUNCS([malloc free strcmp strncmp strcpy strncpy strdup calloc \
                sprintf snprintf printf fprintf memcpy])
AC_CHECK_FUNCS([fopen fseek fread fputs])
AC_CHECK_FUNCS([rand srand time atoi])
AC_CHECK_FUNCS([ntohs htons ntohl htonl])
AC_CHECK_FUNCS([getopt isprint abort exit])
AC_CHECK_FUNCS([stat toupper])
AC_CHECK_FUNCS([strtok strtok_r strchr strstr strtol strtoll])
AC_CHECK_FUNCS([inet_pton])
AC_CHECK_FUNCS([strncasecmp])
# TODO: make this portable
AC_CHECK_FUNC([strnlen], [], [AC_MSG_ERROR([No strnlen implementation found])])

# FIXME(antonin): this is gcc specific
# check for __BYTE_ORDER__
AC_PREPROC_IFELSE(
  [AC_LANG_SOURCE([[
    #ifndef __BYTE_ORDER__
      #error bad
    #endif
    #ifndef __ORDER_BIG_ENDIAN__
      #error bad
    #endif]])],
  [],
  [AC_MSG_FAILURE([Compiler does not define '__BYTE_ORDER__' preprocessor macro])])

# Check for libjudy
AC_CHECK_LIB([Judy], [Judy1Next], [], [AC_MSG_ERROR([Missing libJudy])])

AC_CHECK_LIB([readline], [readline], [], [AC_MSG_ERROR([Missing readline lib])])

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T

AC_SUBST([AM_CPPFLAGS], ["-DPI_LOG_ON -I$INCLUDE_DIR"])
AC_SUBST([AM_LDFLAGS], ["-L$LIB_DIR"])
AC_SUBST([AM_CFLAGS], ["-Wall -Werror -Wextra"])

# Generate makefiles
AC_CONFIG_FILES([Makefile
                 CLI/Makefile
                 examples/Makefile
                 generators/Makefile
                 inc/Makefile
                 src/Makefile
                 src/frontends/Makefile
                 src/frontends/generic/Makefile
                 targets/Makefile
                 targets/dummy/Makefile
                 tests/Makefile
                 third_party/Makefile
                 third_party/cJSON/Makefile
                 third_party/unity/Makefile])

AS_IF([test "$want_bmv2" = yes], [AC_CONFIG_SUBDIRS([targets/bmv2])])

AC_OUTPUT

AS_IF([test "$want_bmv2" = no && test "x$CXX" = x], [
  AS_ECHO("No C++ compiler detected but you are fine because you did not use --with-bmv2")
])

AS_ECHO("")
AS_ECHO("Features recap ......................")
AS_ECHO("Compile for bmv2 .............. : $want_bmv2")
