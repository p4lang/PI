## Arbitration

This server implementation of P4Runtime supports master-slave arbitration. In
P4Runtime each client needs to open a bi-directional stream connection to the
server using the `StreamChannel` RPC. The client should advertise its election
id right away using a `MasterArbitrationUpdate` message. The process through
which election ids are allocated to clients is out-of-scope of P4Runtime and of
this document. The client with the highest election id is referred to as the
"master", while all other clients are referred to as "slaves".

Only the master client can successfully:
- perform `Write` requests
- receive `PacketIn` messages
- send `PacketOut` messages

### `MasterArbitrationUpdate` client request

- if this is the first `MasterArbitrationUpdate` message sent by the client:
  - if the election id is already used by another client connection, the server
    should terminate the stream by returning an `INVALID_ARGUMENT` error.
  - otherwise, if the max number of clients supported by the server is exceeded,
    the server should terminate the stream by returning a `RESOURCE_EXHAUSTED`
    error.
  - otherwise, the client is added to the server's client list.

- if the client is already registered with the server and sends a new
  `MasterArbitrationUpdate` message:
  - if the device id does not match the current one, the server should terminate
    the stream by returning a `FAILED_PRECONDITION` error.
  - otherwise, if the election id matches the current one, nothing happens
  - otherwise, if the new election id is already used by another client
    connection, the server should terminate the stream by returning an
    `INVALID_ARGUMENT` error.
  - otherwise, the server updates the election id for that client.

### `MasterArbitrationUpdate` client response

- if the mastership changed following a `MasterArbitrationUpdate` client
  request, all existing clients are sent a `MasterArbitrationUpdate` message by
  the server. The `device_id` and `election_id` fields must be set
  correctly. The `status` field's code is `OK` for the master, `ALREADY_EXISTS`
  for all the slaves.

- otherwise, only the client which sent the request is notified, assuming its
  election id changed (new connection or election id updated). The `device_id`
  and `election_id` fields must be set correctly. The `status` field's code is
  `OK` if that client is the master, `ALREADY_EXISTS` if it is a slave.

### Packet-in

Only the master receives `PacketIn` messages. If there is no master (i.e. no
client connections), packets are dropped.

### Packet-out

Only the master can send `PacketOut` messages. In all other cases, the message
is dropped.

### Write requests

Only the master can send `WriteRequest` messages. If a slave tries to issue a
`Write`, error code `PERMISSION_DENIED` is returned. The master is indetified by
using the `election_id` field. Note that all clients are trusted; we do not
support the case where a client is using an incorrect `election_id` in his
`WriteRequest` messages.

Note that for the sake of debugging and testing, we accept `WriteRequest`
messages when there is no master (i.e. no client connections) and the
`election_id` field is not set.

### Read requests

Everyone can perform a `Read`, even clients who haven't opened the
bi-directional stream and advertised an election id.
