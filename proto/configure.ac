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

PKG_CHECK_MODULES([PROTOBUF], [protobuf >= 3.0.0])
dnl Not necessary for recent autoconf versions but I think it makes things more
dnl readable
AC_SUBST([PROTOBUF_CFLAGS])
AC_SUBST([PROTOBUF_LIBS])

PKG_CHECK_MODULES([GRPC], [grpc >= 1.0.0 grpc++ >= 1.0.0])
AC_SUBST([GRPC_CFLAGS])
AC_SUBST([GRPC_LIBS])

AC_PATH_PROG([PROTOC], [protoc], [])
AS_IF([test "x$PROTOC" = x], [AC_MSG_ERROR([protoc not found])])

AC_PATH_PROG([GRPC_CPP_PLUGIN], [grpc_cpp_plugin])
AS_IF([test "x$GRPC_CPP_PLUGIN" = x], [
    AC_MSG_ERROR([grpc_cpp_plugin not found])
])

# Generate makefiles
AC_CONFIG_FILES([Makefile
                 p4info/Makefile])

AC_OUTPUT
