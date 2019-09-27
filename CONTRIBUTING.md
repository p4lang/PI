You can fork the repo and submit a pull request in Github. For more information
send us an email (p4-dev@lists.p4.org).

### Apache CLA

All developers must sign the [P4.org](http://p4.org) CLA and return it to
(membership@p4.org) before making contributions. The CLA is available
[here](https://p4.org/assets/P4_Language_Consortium_Membership_Agreement.pdf).

### Building locally

We recommend that you build with a recent C/C++ compiler and with `-Werror`
since our CI tests use this flag.

### Style checker

All contributed code must pass the style checker, which can be run with
`./tools/check_style.sh`. If the style checker fails because of a C file, you
can format this C file with `./tools/clang_format_check.py -s Google -i <file>`.

CI uses clang-format-6.0 to validate the formatting of C files, which means that
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
