ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

AM_TESTS_ENVIRONMENT = export PI_TEST_WITH_VALGRIND=1;

TESTS = \
table_dump.test \
table_dump_valid.test \
table_indirect.test \
table_wkey.test \
device_commands.test \
counter.test \
counter_direct.test \
meter.test \
meter_direct.test \
counter_and_meter_direct.test \
direct_res_reset.test \
device_update.test \
act_prof.test

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
table_wkey.test \
testdata/table_wkey.in \
testdata/table_wkey.out \
device_commands.test \
testdata/device_commands.in \
testdata/device_commands.out \
act_prof.test \
testdata/act_prof.in \
testdata/act_prof.out

EXTRA_DIST += \
testdata/stats.json \
counter.test \
testdata/counter.in \
testdata/counter.out \
counter_direct.test \
testdata/counter_direct.in \
testdata/counter_direct.out \
meter.test \
testdata/meter.in \
testdata/meter.out \
meter_direct.test \
testdata/meter_direct.in \
testdata/meter_direct.out \
counter_and_meter_direct.test \
testdata/counter_and_meter_direct.in \
testdata/counter_and_meter_direct.out \
direct_res_reset.test \
testdata/direct_res_reset.in \
testdata/direct_res_reset.out

EXTRA_DIST += \
device_update.test \
testdata/device_update.in \
testdata/device_update.out \
testdata/swap_1.json \
testdata/swap_2.json
