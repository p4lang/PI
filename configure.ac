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

# TODO: make this conditional on the PD if possible
AM_PATH_PYTHON([2.7],, [:])

want_bmv2=no
AC_ARG_WITH([bmv2],
    AS_HELP_STRING([--with-bmv2], [Build for bmv2 target]),
    [want_bmv2=yes], [])

AM_CONDITIONAL([WITH_BMV2], [test "$want_bmv2" = yes])

want_fe_cpp=no
AC_ARG_WITH([fe_cpp],
    AS_HELP_STRING([--with-fe-cpp], [Build with C++ frontend]),
    [want_fe_cpp=yes], [])

AM_CONDITIONAL([WITH_FE_CPP], [test "$want_fe_cpp" = yes])

LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# Checks for header files.
AC_LANG_PUSH(C)

# check for pthreads
AX_PTHREAD()

# To simplify usage, we will update PATH, CPPFLAGS,.. to include the 'prefix'
# ones
adl_RECURSIVE_EVAL([$bindir], [BIN_DIR])
adl_RECURSIVE_EVAL([$includedir], [INCLUDE_DIR])
adl_RECURSIVE_EVAL([$libdir], [LIB_DIR])

simple_switch_found=no
AS_IF([test "$want_bmv2" = yes], [
    AC_PATH_PROG([BM_SIMPLE_SWITCH], [simple_switch], [],
      [$PATH$PATH_SEPARATOR$BIN_DIR])
    AS_IF([test x"$BM_SIMPLE_SWITCH" = x], [
      AC_MSG_WARN([You are compiling for bmv2, \
                   but simple_switch binary was not found, \
                   we won't run the tests requiring simple_switch])], [
      simple_switch_found=yes])
])
AM_CONDITIONAL([WITH_SIMPLE_SWITCH], [test "$simple_switch_found" = "yes"])
AM_CONDITIONAL([WITH_CLI_TESTS], [test "$simple_switch_found" = "yes"])

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
                 bin/Makefile
                 CLI/Makefile
                 examples/Makefile
                 frontends_extra/Makefile
                 generators/Makefile
                 generators/pd/Makefile
                 include/Makefile
                 lib/Makefile
                 src/Makefile
                 targets/Makefile
                 targets/dummy/Makefile
                 targets/rpc/Makefile
                 tests/Makefile
                 tests/CLI/Makefile
                 third_party/Makefile
                 third_party/cJSON/Makefile
                 third_party/unity/Makefile])

AS_IF([test "$want_bmv2" = yes], [AC_CONFIG_SUBDIRS([targets/bmv2])])
AS_IF([test "$want_fe_cpp" = yes], [
  AC_CONFIG_SUBDIRS([frontends_extra/cpp])
])
AM_COND_IF([WITH_CLI_TESTS],
           AC_CONFIG_FILES([tests/CLI/run_one_test.py],
                           [chmod +x tests/CLI/run_one_test.py]))

AC_OUTPUT

AS_IF([test "$want_bmv2" = no && test "x$CXX" = x], [
  AS_ECHO("No C++ compiler detected but you are fine because you did not use --with-bmv2")
])

AS_ECHO("")
AS_ECHO("Features recap ......................")
AS_ECHO("Compile for bmv2 .............. : $want_bmv2")
AS_IF([test "$want_bmv2" = yes], [
AS_ECHO("  simple_switch found ......... : $simple_switch_found")
])
AS_ECHO("Compile CPP frontend .......... : $want_fe_cpp")
