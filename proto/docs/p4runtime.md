# P4Runtime User Documentation

**Contributors:**
Yavuz Yetim, Antonin Bas, Waqar Mohsin, Tom Everman, Samar Abdi

**Date:**
October 2nd, 2017

**Version:**
0.1: This is a WIP draft and we will improve other issues such as sharding.

This document describes the rules and conventions for the P4Runtime API for a
switch. This document's goals:

*   Ensure that the run-time API is unambiguous. A data type should mean the
    same thing to both the client and the server (e.g., same endianness for a
    protobuf byte string).
*   Canonicalize data representations. If a data type has multiple possible
    representations for the same meaning then we pick one of these as the
    canonical format.
*   Avoid undefined behavior by raising an *invalid argument error* for any
    unexpected message.

## Read/write symmetry

The reads and writes a client issues towards a server should be symmetrical and
unambiguous. More specifically, if a client writes to a P4 object and then reads
it back then the client should expect that the message it wrote and the message
it read should match if the RPCs finished successfully. Consider the following
pseudocode as an example:

```python
intended_value = value

status = server.write(intended_value, p4_object)
observed_value = server.read(p4_object)

assert(intended_value == observed_value)
```

To ensure read-write symmetry, the rest of the doc tries to offer canonical
representations for various data types, but this principle should be thought of
where it falls short. Ensuring this will allow a controller software to recover
programmatically from failures that can affect the switch stack software,
communication channel, or the controller replicas. If Read RPC returns a
semantically-same but syntactically-different response then the client would
have to canonicalize the read values to check its internal state, which only
pushes the protocol's complexities to the client implementations.

### Map-like message sequences

Map-like messages, i.e., messages that contain an ID and a value (e.g.,
`field_id`, and a field value in `FieldMatch`), are common in P4Runtime. Because
every entry contains a unique ID, reordering them yields semantically-equivalent
messages.

For map-like data structures, we make an exception to the "syntactically-same"
rule and use semantic equivalence to avoid requiring the switch to remember the
field order. Therefore, the controller is expected to use a check similar to the
following Python snippet in deciding the equality of two map-like structures:

```python
def Equal(map_like_x, map_like_y):
  # Parse structures into maps.
  map_x = dict()
  for i, v := map_like_x:
    map_x[i] = v

  map_y = dict()
  for i, v := map_like_x:
    map_y[i] = v

  # Check map equivalence.
  return map_x == map_y
```

## Byte strings

P4Runtime data sizes may be large enough to not fit in common data types that
largely follow a host machine's word sizes, i.e., 32 or 64 bits. The P4 language
does not put any limit on the header fields or action parameters a switch can
operate on, and it is up to a P4 program to determine them. Due to the
flexibility of data sizes, P4Runtime declares them to be byte strings of any
integer size.

### Byte string length

The server ensures that the byte string for each data type has the correct size
with respect to the definition of the data type within the P4 program, and
returns *error* otherwise:

```python
bytestring_length = (num_bits_in_bitfield_in_p4_program + 7) / 8
```

### Byte order

For all byte strings with size larger than 0 P4Runtime uses big endian (i.e.,
network) byte order.

## Value formats and constraints for P4Runtime fields

This section describes some requirements on the values the fields in the
P4Runtime can have. This is to ensure a canonical representation as described
earlier. The server should handle fields as follows (using p4runtime.proto
format):

### `TableEntry.match`, `FieldMatch.field_id`, and other fields of the `FieldMatch`

Controller leaves `match` as unspecified and sets the `is_default_action` field
to true when it wants to change the default action within a table. The following
table illustrates this use case. The ids in the comments refer to the P4 compiler
assigned ids to the entities. We assume that both actions `bar` and `baz` do not
take any arguments.

```
table foo {             // table id: 1
  key = {
    hdr.foo : ternary;  // field id: 10
  }
  actions = {
    bar;                // action id: 20
    baz;                // action id: 21
  }
  default_action = baz();
}
```

The following table entry will change the default action from `baz()` to `bar()`.
```
table_entry {
  table_id: 1
  action {
    action {
      action_id: 20  ## bar action id
    }
  }
  priority: 9
  controller_metadata: 0
  is_default_action: true
}
```

If `match` for a field is not defined, then the field is treated as don't care
when constructing the match key for the table entry. Note that leaving match field
undefined is only allowed for ternary, LPM and range fields. The following table
entry will program a flow in table `foo` (above) that matches all packets and
performs action `baz`. Notice the missing fields for `match` and
`is_default_action`.

```
table_entry {
  table_id: 1
  action {
    action {
      action_id: 21  ## baz action id
    }
  }
  priority: 9
  controller_metadata: 0
}
```

As long as `match` exists, `field_id` and the `oneof` match specification must
exist (e.g., `FieldMatch.Ternary`). The subfields of `FieldMatch` are subject
to the constraints listed below.

Convention: The code below follows C++ syntax, but skips verbosity such as
semicolon and `break` statements. Further, consider a function `p4_type()` that
returns the `field_match_type` from a given P4 program, and a `parseInteger()`
function that parses the given string to an Integer-like type. This function is
discussed in sections describing byte and bit value formats.

```
switch(p4_type(match.field_id())) {
  case EXACT:
    assert(match.has_exact() && !match.exact().value().empty())
  case TERNARY:
    assert(match.has_ternary())
    assert(!match.ternary().value().empty() && !match.ternary().mask().empty())
  case LPM:
    assert(match.has_lpm())
    assert(!match.lpm().value().empty() && match.lpm().prefix_len() > 0)
  case RANGE:
    Integer low, high;
    assert(match.has_range())
    assert(parseInteger(match.range().low(), &low))
    assert(parseInteger(match.range().high(), &hi))
    assert(low <= high)
  case VALID:
    assert(match.has_valid())
}
```

### Actions

`Action`s should always be populated for every insert action (e.g., an
`ActionProfileMember` insertion, or a `TableEntry` insertion). Further, the
following should hold:

```
for (auto param: action.param())
  assert(param.has_value())
```

### Packet IO

The following fields should always be set: `PacketOut.payload`,
`PacketIn.payload`, `PacketMetadata.value`.

### Config

`ForwardingPipelineConfig.p4_device_config`: Handling of this message and its
existence or non-existence is target-dependent.

## Sub-byte bit location

Data sizes in the P4 language are at *bit* granularity. However, data sizes in
transmission protocols, such as protobuf, are at *byte* granularity. Sub-byte
bits within a byte are expected to appear as the lowest significant bits. Any
bit set higher than the P4-program size should raise an *error*.

Combined with the big-endianness assumption, this gives an intuitive layout for
any data type. E.g., For a bit field of size 20 that has all bits set, the
resulting byte string has length 3 and would appear as:

```
 byte 2      byte 1      byte 0
--------    --------    --------
00001111    11111111    11111111
       |           |           |
  bit 16       bit 8       bit 0
```

## Integer data types and IDs

p4runtime.proto already represents every integer data type as

-   signed if it is expected to perform any arithmetic on the field, and
-   as unsigned if that is not the case and that the field is intended as an ID
    or a bit vector.

### Zero as a reserved value

p4runtime.proto uses proto3 syntax, and so it does not allow *not specifying* a
scalar data type, such as a uint32. Therefore, we reserve value 0 for those
fields to mean *unset*. Therefore, it is an *error* to specify 0 for any P4
object ID in a non-read request towards the switch, such as in a `WriteRequest`
or a `SetForwardingPipelineConfigRequest`.

## Direct resources

Direct resources, i.e., `DirectMeterEntry` and `DirectCounterEntry`, are bound
to `TableEntry`s and therefore their insertion, deletion, and configuration are
subject to the following constraints:

- Direct resources cannot be inserted or deleted independent of their
  `TableEntry`s. However, they can be modified independently.
- Direct resources should be configured when their `TableEntry` is inserted.

## Reading (querying) P4 Object State from the Switch

### Row selection

In all *query*-like requests, the API allows for expressing *all* functionality
by

-   not specifying a message field, or
-   giving 0 for a field of a scalar data type (such as for an uint32 ID).

For example, the client can issue the following `ReadRequest` to read all
entities from all devices that a runtime server manages:

```
device_id: 0
```

In order to read all tables from a specific device 3, the client can send:

```
device_id: 3
entities {
  table_entry {
    table_id: 0
    priority: 0
    controller_metadata: 0
  }
}
```

`device_id` above is a key-like field, and the query filtering also occurs on
value-like fields as well. For example, the following proto returns *only* the
`table_entry`s from table `7` whose priorities are `3`:

```
device_id: 3
entities {
  table_entry {
    table_id: 7
    priority: 3
    controller_metadata: 0
  }
}
```

### Column selection

In all *query*-like requests, all the entry fields should be returned. Query
requests use a key to identify an entry (e.g., `id` for an `ActionProfileGroup`)
and the switch is expected to return all the state it has for that entry.

`TableEntry` and direct resources have overlapping fields, and so the switch
should take into account the top-level message and act as follows:

- If the `ReadRequest` contains a `TableEntry` then table entry returned as a
  response should include any counter and meter state that may exist.

- However, if the `ReadRequest` instead contains `DirectCounterEntry` then the
  switch only returns the counter state associated with the match given in
  `DirectCounterEntry.TableEntry.match`, and does not populate other fields
  within the `TableEntry` (such as `Action`).
