ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_TESTS_ENVIRONMENT = export PI_TEST_WITH_VALGRIND=1;

TESTS = \
table_dump.test \
table_dump_valid.test \
table_indirect.test \
device_commands.test \
counter.test \
counter_direct.test

# test_config.py.in included by default
EXTRA_DIST = \
run_one_test.py \
test.supp \
table_dump.test \
testdata/table_dump.in \
testdata/table_dump.out \
testdata/simple_router.json \
table_dump_valid.test \
testdata/table_dump_valid.in \
testdata/table_dump_valid.out \
testdata/valid.json \
table_indirect.test \
testdata/table_indirect.in \
testdata/table_indirect.out \
testdata/ecmp.json \
device_commands.test \
testdata/device_commands.in \
testdata/device_commands.out \
testdata/stats.json \
counter.test \
testdata/counter.in \
testdata/counter.out \
counter_direct.test \
testdata/counter_direct.in \
testdata/counter_direct.out
