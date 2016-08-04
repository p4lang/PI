# Specification of PI data formats

This document is targeted at developpers who need to implement a PI frontend or
a target-specific backend. PI uses efficient formats to pass data from the
frontend all the way to a target backend (e.g. for the match key). This document
describes these formats at the byte level.

## Match key

The `pi_match_key_t` struct is defined in [include/PI/int/pi_int.h]
(../include/PI/int/pi_int.h) as follows:
```
struct pi_match_key_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t table_id;
  size_t data_size;
  char *data;
};
```

It is each frontend's responsibility to populate the different fields of the
struct. In this section, we will be describing the `data` field, which is a byte
array. This array is used to store the values of the different match fields for
this specific match-table entry. Each field value is serialized to the byte
array in the order in which it appears in the P4 program. The serialization
routine depends on the match type for the field, and operates according to the
following rules:

### Valid match

One byte is used. The byte value is 0 if and only if the field is not valid. If
the field is valid, any non-zero value in the range [1, 255] can be used.

### Exact match

The number of bytes used is equal to the width, in bytes, of the P4 field. If
the field's bitwidth is not a multiple of 8, we round-up to the nearest
byte. Each byte of the field value is serialized, in network-byte order. If the
field is not byte-aligned, '0' bits are used to pad the first byte (i.e. the
most-significant bits of the first byte are set to 0).

### LPM match

Same as for [exact match] (#exact-match), but an additional 4 bytes are used to
serialize the prefix length. Unlike for the field value, the prefix length is
serialized in little-endian order.

### Ternary match

The number of bytes used is equal to twice the width, in bytes, of the P4
field. The field value is serialized first, then the mask, as per the
description [above] (#exact-match).

### Range match

As for [ternary match] (#ternary-match). the number of bytes used is twice the
width of the match field. The 'start' of the range is serialized first, followed
by the 'end' of the range.

### Match key example

Let's consider the following P4 table:
```
table t_example {
  fields {
    meta.port    : range;    // a 16-bit field
    meta.ipv4    : lpm;      // a 32-bit field
    meta.vlan    : exact;    // a 12-bit field
    meta.hdr     : valid;    // some header
    meta.macAddr : ternary;  // a 48-bit field
  }
}
```
The size of the match key `data` byte array will be:
```
2 * byte_size(meta.port) +
byte_size(meta.ipv4) + 4 +
byte_size(meta.vlan) +
1 +
2 * byte_size(meta.macAddr)
= 4 + 8 + 2 + 1 + 12 = 27 bytes
```
Now let's assume that we want to add an entry to this table with the following
match key:
```
(meta.port=0->1024, meta.ipv4=10.0.0.1/12, meta.vlan=0xabc, meta.hdr=valid,
 meta.macAddr=a0:88:00:00:00:00&&&ff:ff:00:00:00:00)
```
Then the `data` byte array could contain the following data (in hexadecimal):
```
00 | 00 | 04 | 00 |
0a | 00 | 00 | 01 | 0c | 00 | 00 | 00 |
0a | bc |
01 |
a0 | 88 | 00 | 00 | 00 | 00 |
ff | ff | 00 | 00 | 00 | 00
```

### Some remarks

 * As you can see from the previous [example] (#match-key-example), the size of
   the key could be further reduced. It is not necessary to dedicate 4 bytes to
   the prefix length. It is also not necessary to explicitly represent
   information which is masked off (in the case of a lpm or ternary match). We
   may optimize the format of the match key later on, even though it may make
   manipulating the match key data more complicated for the implementation.
 * With the current format, `data` byte array always has the same size for a
   given match table. This is very convenient since the same memory can be
   re-used for all "table add" operations for a given table.
 * Masked-off bits (for a lpm or ternary match) can be set to any value. Target
   backends should ignore these bits.

## Action data

The `pi_action_data_t` struct is defined in [include/PI/int/pi_int.h]
(../include/PI/int/pi_int.h) as follows:
```
struct pi_action_data_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t action_id;
  size_t data_size;
  char *data;
};
```

As for the match key, it is each frontend's responsibility to populate the
different fields of the struct. In this section, we will be describing the
`data` field, which is a byte array. This array is used to store the values of
the different arguments to be used by the action function. Each argument is
serialized into the byte array, in the order in which it appears in the P4
program. As for the match key, each argument is serialized in network-byte order
and each serialized value is byte-aligned (with '0' bit padding if necessary).

### Action data example

Let's consider the following P4 action:
```
action a_example(p32 /* 32-bit */, p12 /* 12-bit */, p64 /* 64 bit */) {
  // ...
}
```
The size of the action data `data` byte array will be: `4 + 2 + 8 = 14 bytes`.
Let's assume that we want to use the following action data in our new table
entry: `(p32=87534,p12=0xabc,p64=0x1122334455667788)`. The `data` byte array
will contain the following bytes (represented here in hexadecimal):
```
00 | 01 | 55 | ee |
0a | bc |
11 | 22 | 33 | 44 | 55 | 66 | 77 | 88
```

### Some remarks

 * As for match keys, the `data` byte array always has the same size for a given
   action function. This is very convenient since the same memory can be re-used
   for all "table add" operations for a given action.

## Result of table fetch

The PI provides a method to retrieve all the match entries in a table. The
result is stored in an instance of the `pi_table_fetch_res_t` struct, which is
defined in [include/PI/int/pi_int.h] (../include/PI/int/pi_int.h) as follows:
```
struct pi_table_fetch_res_s {
  const pi_p4info_t *p4info;
  pi_p4_id_t table_id;
  size_t num_entries;
  size_t mkey_nbytes;
  size_t idx;
  size_t curr;
  size_t entries_size;
  char *entries;
  // just pointers to entries byte array
  struct pi_match_key_s *match_keys;
  struct pi_action_data_s *action_datas;
  struct pi_entry_properties_s *properties;
  // TODO: direct resources
};
```

It is each target backend's responsibility to populate 3 members of this data
structure: `num_entries`, `mkey_nbytes` (the size of the serialized match key in
bytes), `entries` and `entries_size` (the size in bytes of the `entries` byte
array). Here, the `entries` member is a (huge) byte array which includes, for
each match entry:
 * entry handle
 * match key
 * action id
 * action data
 * entry properties (e.g. priority when appropriate)
 * direct resources associated with the entry (TODO)

For each match entry handle, we serialize the above information as follows:

 * the entry handle, as 8 bytes in little-endian order
 * the serialized match key, as described [above] (#match-key)
 * the action entry type: 0 (`PI_ACTION_ENTRY_TYPE_NONE`), 1
   (`PI_ACTION_ENTRY_TYPE_DATA`) or 2 (`PI_ACTION_ENTRY_TYPE_INDIRECT)
 * the action entry:
   * for `PI_ACTION_ENTRY_TYPE_NONE`: nothing
   * for `PI_ACTION_ENTRY_TYPE_DATA`:
     * the action id, as 4 bytes in little-endian order
     * the size of the serialized action data in bytes, as 4 bytes in
       little-endian order
     * the serialized action data, as described [above] (#action-data)
   * for `PI_ACTION_ENTRY_TYPE_INDIRECT`: the indirect handle, as 8 bytes in
     little-endian order
 * the entry properties; see description [below] (#entry-properties)
 * TODO: direct resources

The target backend code does not need to worry about the other members of the
structure. If the backend does populate these fields, the values will be
overwritten by the PI code.

This structure is not seen by the application, which instead can iterate through
the entries using `pi_table_entries_next`.

### Entry properties

The entry properties (for now priority and TTL) are serialized as 4 bytes to
indicate which properties are valid, followed by 4 bytes for each valid
property:
 * the first 4 bytes constitute a bitmap which indicates which properties are
 valid. The bitmap is serialized in little-endian order. The bit position of
 each property is given by the corresponding `pi_entry_property_type_t` enum
 value.
 * as of now, each property is encoded by a `uint32_t` integer; we simply
 serialize this integer in little-endian format.
