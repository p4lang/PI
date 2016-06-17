ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_TESTS_ENVIRONMENT = export PI_TEST_WITH_VALGRIND=1;

TESTS = \
table_dump.test \
table_dump_valid.test

# test_config.py.in included by default
EXTRA_DIST = \
run_one_test.py \
table_dump.test \
testdata/table_dump.in \
testdata/table_dump.out \
testdata/simple_router.json \
table_dump_valid.test \
testdata/table_dump_valid.in \
testdata/table_dump_valid.out \
testdata/valid.json
