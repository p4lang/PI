I don't know how long this code will be around. I have chosen to write it in
Python to save time. It loads a "native" json dump of the p4info "DB" and
generates the PD wrapper for the PI API. Most of this code was copied from
[p4c-bm] (https://github.com/p4lang/p4c-bm). Of course it is much more concise
since at this time we don't support anything "advanced" (e.g. resources like
meters / counters), but only simple table operations.

As of now, I only generate `pd_tables.c` and needed headers. I check my template
code by cd'ing into the generated directory and running:

     gcc -c src/pd_tables.c -I. -I../../../include

The `pd_common.h` header is going to be quite an issue. As of today, each target
comes with its own header (bmv2 + tofino)...
