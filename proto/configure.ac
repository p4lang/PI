#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([PI-proto], [0.1], [])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_CXX
LT_INIT

AC_CONFIG_MACRO_DIR([m4])

AC_LANG_PUSH(C)
AC_LANG_PUSH(C++)

AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])

AM_PATH_PYTHON([2.7],, [:])
AM_CONDITIONAL([HAVE_PYTHON], [test "$PYTHON" != :])

PKG_CHECK_MODULES([PROTOBUF], [protobuf >= 3.0.0])
dnl Not necessary for recent autoconf versions but I think it makes things more
dnl readable
AC_SUBST([PROTOBUF_CFLAGS])
AC_SUBST([PROTOBUF_LIBS])

dnl we need >= 1.3.0 so that binary error details (libgrpc++_error_details) are
dnl available
PKG_CHECK_MODULES([GRPC], [grpc++ >= 1.3.0 grpc >= 3.0.0])
AC_SUBST([GRPC_CFLAGS])
AC_SUBST([GRPC_LIBS])

AC_PATH_PROG([PROTOC], [protoc], [])
AS_IF([test "x$PROTOC" = x], [AC_MSG_ERROR([protoc not found])])

AC_PATH_PROG([GRPC_CPP_PLUGIN], [grpc_cpp_plugin])
AS_IF([test "x$GRPC_CPP_PLUGIN" = x], [
    AC_MSG_ERROR([grpc_cpp_plugin not found])
])
AS_IF([test "$PYTHON" != :], [
    AC_PATH_PROG([GRPC_PY_PLUGIN], [grpc_python_plugin])
    AS_IF([test "x$GRPC_PY_PLUGIN" = x], [
        AC_MSG_WARN([grpc_python_plugin not found, Python code won't be generated])
    ])
])
AM_CONDITIONAL([HAVE_GRPC_PY_PLUGIN], [test "x$GRPC_PY_PLUGIN" != x])

want_bmv2=no
AC_ARG_WITH([bmv2],
    AS_HELP_STRING([--with-bmv2], [Build for bmv2 target]),
    [want_bmv2="$withval"], [])

AM_CONDITIONAL([WITH_BMV2], [test "$want_bmv2" = yes])

with_proto_demo=yes
AC_CHECK_LIB([microhttpd], [MHD_start_daemon], [], [
    AC_MSG_WARN([microhttpd library not found, will not compile demo])
    with_proto_demo=no
])
# TODO(antonin): demo also uses boost_system

AM_CONDITIONAL([WITH_PROTO_DEMO], [test "$with_proto_demo" = yes])

dnl cannot use the path below, which would break 'make dist'
dnl googleapis_check_f=$ac_abs_confdir/googleapis/google/rpc/status.proto
googleapis_check_f=$ac_abs_confdir/google/rpc/status.proto
AC_CHECK_FILE([$googleapis_check_f], [],
              [AC_MSG_ERROR([Did you run 'git submodule update --init'?])])

# check for pthreads
AX_PTHREAD([], [AC_MSG_ERROR([Missing pthread library])])

AC_SUBST([AM_CXXFLAGS], ["$PTHREAD_CFLAGS -Wall -Werror -Wextra"])

# Determine the right way to ignore unresolved symbols in shared libraries.
# Unfortunately this varies by platform. Right now we assume that on non-Darwin
# operating systems, GNU ld is in use.
AC_CANONICAL_HOST
case "${host_os}" in
    darwin*)
        AC_SUBST([LD_IGNORE_UNRESOLVED_SYMBOLS], ["-Wl,-undefined,dynamic_lookup"])
        ;;
    *)
        AC_SUBST([LD_IGNORE_UNRESOLVED_SYMBOLS], ["-Wl,--unresolved-symbols=ignore-in-shared-libs"])
        ;;
esac

AC_PROG_SED

# Generate makefiles
AC_CONFIG_FILES([Makefile
                 p4info/Makefile
                 frontend/Makefile
                 server/Makefile
                 demo_grpc/Makefile
                 tests/Makefile
                 third_party/Makefile])

AC_OUTPUT

AS_ECHO("")
AS_ECHO("Features recap ......................................")
AS_ECHO("Compile demo_grpc ............................ : $with_proto_demo")
