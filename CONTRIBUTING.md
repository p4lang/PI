You can fork the repo and submit a pull request in Github. For more information
send us an email (p4-dev@lists.p4.org).

### Apache CLA

All developers must sign the [Open Networking Foundation (ONF)
CLA](https://cla.opennetworking.org) before making contributions.

### Inclusive Naming

For symbol names and documentation, do not introduce new usage of harmful
language such as 'master / slave' (or 'slave' independent of 'master') and
'blacklist / whitelist'. For more information about what constitutes harmful
language and for a reference word replacement list, please refer to the
[Inclusive Naming Initiative](https://inclusivenaming.org/).

We are committed to removing all harmful language from the project. If you
detect existing usage of harmful language in code or documentation, please
report the issue to us or open a Pull Request to address it directly. Thanks!

### Building locally

We recommend that you build with a recent C/C++ compiler and with `-Werror`
since our CI tests use this flag.

### Style checker

All contributed code must pass the style checker, which can be run with
`./tools/check_style.sh`. If the style checker fails because of a C file, you
can format this C file with `./tools/clang_format_check.py -s Google -i <file>`.

CI uses clang-format-8 to validate the formatting of C files, which means that
your contribution may fail CI if you use a different version locally.

### Making changes to the PI internal API

The PI internal API is the list of functions that target devices / platforms
must implement. All headers can be found under
[include/PI/target](include/PI/target). Any change to this API can have a big
impact as target-specific PI implementations may need to be updated to be able
to work with the latest version of the PI library. If you make such a change,
you need to increment `PI_ABI_VERSION` in
[include/PI/int/pi_int.h](include/PI/int/pi_int.h). This ensures that we can
detect version mismatch at runtime. In particular, you need to increment
`PI_ABI_VERSION` when:
 * you modify a function belonging to the internal API
 * you add a function to the internal API
