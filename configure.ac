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
# long as --with-bmv2 / --with-fe-cpp / --with-proto is not specified of course)
AC_PROG_CXX

# TODO: make this conditional on the PD if possible
AM_PATH_PYTHON([2.7],, [:])

DX_DOT_FEATURE([ON])
DX_PDF_FEATURE([ON])
DX_HTML_FEATURE([ON])
DX_PS_FEATURE([OFF])
DX_INIT_DOXYGEN([PI], [$(top_srcdir)/docs/doxygen.cfg], [doxygen-out])

want_bmv2=no
AC_ARG_WITH([bmv2],
    AS_HELP_STRING([--with-bmv2], [Build for bmv2 target]),
    [want_bmv2="$withval"], [])

AM_CONDITIONAL([WITH_BMV2], [test "$want_bmv2" = yes])

want_fe_cpp=no
AC_ARG_WITH([fe_cpp],
    AS_HELP_STRING([--with-fe-cpp], [Build with C++ frontend]),
    [want_fe_cpp="$withval"], [])

AC_ARG_WITH([proto],
    AS_HELP_STRING([--with-proto],
                   [Compile p4runtime.proto and associated frontend]),
    [with_proto="$withval"], [with_proto=no])

AS_IF([test "$with_proto" = yes && test "$want_fe_cpp" = no], [
    AC_MSG_NOTICE([C++ frontend needed for p4runtime.proto, turning it on])
    want_fe_cpp=yes
])

AM_CONDITIONAL([WITH_FE_CPP], [test "$want_fe_cpp" = yes])

AM_CONDITIONAL([WITH_PROTO], [test "$with_proto" = yes])
# may add other conditions later for GTEST to be compiled if we use GTEST
# somewhere else
AM_CONDITIONAL([WITH_GTEST], [test "$with_proto" = yes])
AM_COND_IF([WITH_GTEST], [
    gtest_root=$ac_abs_confdir/third_party/googletest
    gtest_check_f=$gtest_root/googletest/src/gtest.cc
    AC_CHECK_FILE([$gtest_check_f], [],
                  [AC_MSG_ERROR([Did you run 'git submodule update --init'?])])
])

AC_ARG_WITH([internal-rpc],
    AS_HELP_STRING([--with-internal-rpc],
                   [Build internal rpc (nanomsg) code @<:@default=yes@:>@]),
    [with_internal_rpc="$withval"], [with_internal_rpc=yes])

AM_CONDITIONAL([WITH_INTERNAL_RPC], [test "$with_internal_rpc" = yes])

AC_ARG_WITH([cli],
    AS_HELP_STRING([--with-cli], [Build PI C CLI @<:@default=yes@:>@]),
    [with_cli="$withval"], [with_cli=yes])

AM_CONDITIONAL([WITH_CLI], [test "$with_cli" = yes])

AC_ARG_ENABLE([Werror],
    AS_HELP_STRING([--enable-Werror], [Make all compiler warnings fatal]),
    [enable_Werror="$enableval"], [enable_Werror=no])

LT_INIT

AC_CONFIG_MACRO_DIR([m4])

# Checks for header files.
AC_LANG_PUSH(C)

# check for pthreads
AX_PTHREAD([], [AC_MSG_ERROR([Missing pthread library])])

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
AM_CONDITIONAL([WITH_SIMPLE_SWITCH], [test "$simple_switch_found" = yes])
AM_CONDITIONAL([WITH_CLI_TESTS],
               [test "$with_cli" = yes\
                && test "$simple_switch_found" = yes\
                && test "$with_internal_rpc" = yes])

AC_CHECK_HEADERS([stdlib.h string.h assert.h stdio.h stdint.h stdbool.h\
                  stddef.h time.h ctype.h unistd.h arpa/inet.h\
                  sys/types.h sys/stat.h inttypes.h],
                 [], [AC_MSG_ERROR([Missing header file])])

AC_CHECK_FUNCS([malloc free strcmp strncmp strcpy strncpy strdup calloc \
                sprintf snprintf printf fprintf memcpy])
AC_CHECK_FUNCS([fopen fseek fread fputs fprintf dprintf])
AC_CHECK_FUNCS([rand srand time atoi])
AC_CHECK_FUNCS([ntohs htons ntohl htonl])
AC_CHECK_FUNCS([getopt isprint abort exit])
AC_CHECK_FUNCS([stat toupper])
AC_CHECK_FUNCS([strtok strtok_r strchr strstr strtol strtoll])
AC_CHECK_FUNCS([inet_pton])
AC_CHECK_FUNCS([strncasecmp])
AC_CHECK_FUNCS([qsort])
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

AM_COND_IF([WITH_CLI], [
  AC_CHECK_LIB([readline], [readline], [],
               [AC_MSG_ERROR([Missing readline lib])])
])

AM_COND_IF([WITH_INTERNAL_RPC], [
  AC_CHECK_LIB([nanomsg], [nn_errno], [], [AC_MSG_ERROR([Missing libnanomsg])])
])

AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T

AC_MSG_CHECKING([if compiling with clang])

AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([], [[
#ifndef __clang__
       not clang
#endif
]])],
[CLANG=yes], [CLANG=no])
AC_MSG_RESULT([$CLANG])

# Enable all warnings. -Wno-tautological-constant-out-of-range-compare is
# necessary because clang is excessively aggressive with this warning and
# complains about some reasonable assertions.
EXTRA_CFLAGS="-Wall -Wextra"
AS_IF([test "$enable_Werror" = "yes"], [EXTRA_CFLAGS="$EXTRA_CFLAGS -Werror"])
AS_IF([test "x$CLANG" = "xyes"],
      [EXTRA_CFLAGS="$EXTRA_CFLAGS -Wno-tautological-constant-out-of-range-compare"])
AC_SUBST([AM_CFLAGS], ["$PTHREAD_CFLAGS $EXTRA_CFLAGS"])

AC_SUBST([AM_CPPFLAGS], ["-DPI_LOG_ON -isystem$INCLUDE_DIR"])
AC_SUBST([AM_LDFLAGS], ["-L$LIB_DIR"])

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
AS_IF([test "$with_proto" = yes], [
  AC_CONFIG_SUBDIRS([proto])
])

AC_OUTPUT

dnl with_proto => want_fe_cpp so we can omit it from the condition
AS_IF([test "x$CXX" = x && test "$want_bmv2" = no && test "$want_fe_cpp" = no], [
  AS_ECHO("No C++ compiler detected but you are fine")
])

AS_ECHO("")
AS_ECHO("Features recap ......................................")
AS_ECHO("Compile for bmv2 ............................. : $want_bmv2")
AS_IF([test "$want_bmv2" = yes], [
AS_ECHO("  simple_switch found ........................ : $simple_switch_found")
])
AS_ECHO("Compile C++ frontend ......................... : $want_fe_cpp")
AS_ECHO("Compile p4runtime.proto and associated fe .... : $with_proto")
AS_ECHO("Compile internal RPC ......................... : $with_internal_rpc")
AS_ECHO("Compile PI C CLI ............................. : $with_cli")
