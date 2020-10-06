#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

ROOT_DIR=$THIS_DIR/..

return_status=0

# used for C files
function run_clang_format() {
    # $1 is directory
    # $2 is style
    find $1 -name '*.h' -o -name '*.c' | xargs -r $THIS_DIR/clang_format_check.py -s $2
    return_status=$(($return_status || $?))
}

# used for C++ files
function run_cpplint() {
    # $1 is directory
    # $2 is root (for include guard)
    python2 $THIS_DIR/cpplint.py --root=$2 $( find $1 -name \*.h -or -name \*.cpp )
    return_status=$(($return_status || $?))
}

run_clang_format $ROOT_DIR/src Google
run_clang_format $ROOT_DIR/include Google
run_clang_format $ROOT_DIR/targets/rpc Google
run_clang_format $ROOT_DIR/targets/dummy Google
run_clang_format $ROOT_DIR/CLI Google
run_clang_format $ROOT_DIR/tests Google
run_clang_format $ROOT_DIR/generators Google
run_clang_format $ROOT_DIR/examples Google
run_clang_format $ROOT_DIR/bin Google
run_clang_format $ROOT_DIR/lib Google

run_cpplint $ROOT_DIR/targets/bmv2
run_cpplint $ROOT_DIR/frontends_extra/cpp frontends_extra/cpp
run_cpplint $ROOT_DIR/proto/p4info
run_cpplint $ROOT_DIR/proto/frontend proto/frontend
run_cpplint $ROOT_DIR/proto/tests
run_cpplint $ROOT_DIR/proto/src
run_cpplint $ROOT_DIR/proto/PI proto
run_cpplint $ROOT_DIR/proto/server

echo "********************************"
if [ $return_status -eq 0 ]; then
    echo "STYLE CHECK SUCCESS"
else
    echo "STYLE CHECK FAILURE"
fi

exit $return_status
