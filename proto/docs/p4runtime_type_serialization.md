# Arbitary P4_16 type serialization in P4Runtime

## Problem statement
The P4_16 language includes more complex types than just bitstrings or even
headers (see [P4_16
specification](https://p4.org/p4-spec/docs/P4-16-v1.0.0-spec.html#sec-p4-type)). Most
of these complex data types can be exposed to the control-plane through table
key expressions, value set lookup expressions, register (PSA extern type) value
types, etc. Not supporting these more compex types can be very limiting. For
example, the following P4_16 objects involve complex types that need to be
exposed in P4Runtime in order to support runtime operations on these objects.

```
value_set<tuple<bit<16>, bit<8> > > pvs_complex;
state parse_ipv4 {
   packet.extract<ipv4_t>(hdr.ipv4);
   transition select({ hdr.ipv4.version, hdr.ipv4.protocol }){
       pvs_complex: parse_inner;
       default: accept;
   }
}
```

```
header_union ip_t {
   ipv4_t ipv4;
   ipv6_t ipv6;
}
Register<ip_t, bit<32> >(128) register_ip;
```

One solution would be to use only bitstrings (`bytes` type) in p4runtime.proto
and to define a custom serialization format for complex P4_16 types. The
serialization would maybe be trivial for header types but would require some
work for header unions, stacks, etc. Rather than coming-up with a serialization
format from scratch, we decided to use a Protobuf representation for all P4_16
types, since the P4Runtime service already uses Protobuf messages.

## P4 type specifications in p4info.proto
In order for the P4Runtime client to generate correctly-formatted messages and
for the P4Runtime service implementation to validate them, P4Info needs to
specify the type of each P4 expression which is exposed to the control-plane. In
the register example above, client and server need to know that each element of
the register has type `ip_t`, which is a header union with 2 possible headers:
`ipv4` with type `ipv4_t` and `ipv6` with type `ipv6`. Similarly, they need to
know the field layout of both these header types.

To achieve this we introduce 2 main protobuf messages: `P4TypeInfo` and
`P4DataTypeSpec`.

`P4TypeInfo` is a top-level member of `P4Info` and includes Protobuf maps
storing the type specification for all the named types in the P4_16
program. These named types are `struct`, `header`, `header_union` and `enum`;
for each of these we have a type specification message, respectively
`P4StructTypeSpec`, `P4HeaderTypeSpec`, `P4HeaderUnionTypeSpec` and
`P4EnumTypeSpec`. We support P4 annotations for named types, which is useful to
identify well-known headers, such as IPv4 or IPv6. `P4TypeInfo` also include the
list of parser errors for the program, as a `P4ErrorTypeSpec` message.

`P4DataTypeSpec` is meant to be used in `P4Info`, everywhere where the P4Runtime
client can provide a value for a P4_16 expression. `P4DataTypeSpec` describes
the compile-time of the expression as a Protobuf `oneof`, which is a `string` in
case of a named type (`struct`, `header`, `header_union` or `enum`), an empty
Protobuf message for `bool` and `error`, and a Protobuf message for other
anonymous types (`bit<W>`, `int<W>`, `varbit<W>`, `tuple` or `stack`). The
"bitstring" types (`bit<W>`, `int<W>` and `varbit<W>`) are grouped together in
the `P4BitstringLikeTypeSpec` message, since they are the only sub-types allowed
in headers and values with one of these types are represented similarly in
P4Runtime (with binary strings).

For all P4_16 compound types (`tuple`, `struct`, `header`, and `header_union`),
the order of members in the `repeated` field of the Protobuf type specification
is guaranteed to be the same as the order of the members in the corresponding
P4_16 declaration. The same goes for the order of members of an `enum` or
members of `error`, as well as for the order of entries in a `stack`.

## P4 data in p4runtime.proto
P4Runtime uses the `P4Data` message to represent values with arbitrary
types. The P4Runtime client must generate correct `P4Data` messages based on the
type specification information included in `P4Info`. The `P4Data` message was
designed to introduce little overhead compared to using binary strings in the
most common case (P4_16 `bit<W>` type).

Just like its `P4Info` counterpart `P4DataTypeSpec`, `P4Data` uses a `oneof` to
represent all possible values.

The order of `members` in `P4StructLike`, the order of `bitstrings` in
`P4Header`, and the order of `entries` in `P4HeaderStack` and
`P4HeaderUnionStack` must match the order in the corresponding `p4info.proto`
type specification and hence the order in the corresponding P4_16 type
declaration.

### `enum` and `error`
We currently use human-readable `string` in `P4Data` to represent `enum` and
`error` values. Indeed, the current P4_16 specification does not specify any
mechanism through which integer values are assigned to `enum` and `error`
members -whether automatically by the compiler or by letting the programmer pick
values. We may switch to an `int32` representation if the P4 language is updated
to specify the underlying representation of enums, in which case we would also
include a mapping from name to integer value in the `P4TypeInfo` message.

## Trade-off for v1.0 release
For the v1.0 release of P4Runtime, the Working Group has decided not to replace
occurences of `bytes` with `P4Data` in the `FieldMatch` message, which is used
to represent table and value set entries. This is to avoid breaking
already-existing implementations of P4Runtime. Similarly it has been decided to
keep using `bytes` to provide action parameter values. However `P4Data` is used
whenever appropriate for PSA externs and we encourage the use of `P4Data` in
architecture-specific extensions.
