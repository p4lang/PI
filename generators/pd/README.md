I don't know how long this code will be around. I have chosen to write it in
Python to save time. It loads a "native" json dump of the p4info "DB" and
generates the PD wrapper for the PI API. Most of this code was copied from
[p4c-bm](https://github.com/p4lang/p4c-bm). Of course it is much more concise
since at this time we don't support anything "advanced" (e.g. resources like
meters / counters), but only simple table operations.

As of now, I only generate `pd_tables.c` and needed headers.

The `pd_common.h` header is going to be quite an issue. As of today, each target
comes with its own header (bmv2 + tofino)... For now I am using the bmv2 one.

`res.thrift` is here temporarily to make compiling the library easier.

To test, you can run `./compile_pd.py ../../tests/testdata/simple_router.json`
from this directory. This is a **temporary** script to compile `libpd.so` and
`libpdthrift.so`.


More advanced test (still temporary):
If you run `make` in this directory, you will obtain a `pdtest` executable. If
run start `simple_switch` and feed it the `test.json`, you can run `./pdtest
native.json`, which will use the generated PD PI-frontend to add an entry to
bmv2, modify it, and then finally delete it. Do not forget to run
`simple_switch` with `--log-console` to check that the entry operations are
correct. Pretty awesome!!!
