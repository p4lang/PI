P4_PREFIX = test
BMV2_JSON_INPUT = test.json
OUT_DIR = pd_out_test

BMV2_LIBS = -lbmpdfixed -lruntimestubs -lsimpleswitch_thrift -lthrift -lnanomsg

PI_LIBS = -Wl,-rpath,. libpd.so \
-Wl,-rpath,../../src/.libs \
-Wl,-rpath,../../src/frontends/generic/.libs \
../../src/.libs/libpi.so \
../../src/frontends/generic/.libs/libpifegeneric.so \
../../targets/bmv2/.libs/libpi_bmv2.a \
../../src/.libs/libpip4info.so

all: pdtest

pdtest: $(BMV2_JSON_INPUT) test.c
	python compile_pd.py --p4-prefix $(P4_PREFIX) -o $(OUT_DIR) $(BMV2_JSON_INPUT)
	g++ -o pdtest -I $(OUT_DIR) test.c $(PI_LIBS) $(BMV2_LIBS)

clean:
	rm -rf $(OUT_DIR)
	rm -f pdtest
