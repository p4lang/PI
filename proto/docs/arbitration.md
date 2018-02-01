## Controller Roles and Mastership Arbitration

P4Runtime supports multiple controller roles to allow partitioning of control plane and P4
objects. For each role, P4Runtime supports master-arbitration across replicated instances
of that controller (to protect against multi-master scenarios). At any given time, only
one of the controller instances (for a given role) is considered a master.

### Controller (or P4Runtime *client*) Role
A given role is identified by `Role.id`.
The `Role.config` describes the role configuration, i.e. what operations, P4 entities,
behaviors, etc. are in the scope of a given role. If `Role.config` is not set,
it implies that all P4 objects and control behaviors are in scope for that role
(i.e. full pipeline access).

The Role IDs are defined offline in agreement across the entire control plane.
A client’s session with P4Runtime is tied to the role ID it passes over the stream
channel (details below). The P4Runtime server will use role ID for two purposes:
- Arbitrate that each role has one and only one master client instance
- Enforce the validity (access control) of P4Runtime requests based on the role config

To keep the protocol simple and extensible, `config` is defined as a `protobuf.Any`,
and concerete defintions are currently outside the scope of P4Runtime.

### *Default* Role
To simplify for use-cases where multiple roles are not needed, the client can leave the
`role` message unset in `MasterArbitrationUpdate`. This implies *default role* and full
pipeline access. This also implies that a default role has a `role.id` of 0 (default).
If using a default role, all RPCs (e.g. `Write`) that pass a `role_id` must set it to
the default(0) value.

### Election ID and Master selection
The election ID is tied to a given role, and must be unique across clients belonging to the
same role. The process through which election IDs are allocated to clients is out-of-scope
of P4Runtime and of this document. For a  given role, the client with the highest election
ID is referred to as the "master", while all other clients are referred to as "slaves".

Only the master client can successfully:
- Perform `Write` requests
- Receive `PacketIn` messages
- Send `PacketOut` messages

### P4Runtime session establishment
To establish a P4Runtime session, a client needs to open a bi-directional
stream connection to the server using the `StreamChannel` RPC. The client should advertise
its `role` and `election_id` right away using a `MasterArbitrationUpdate` message. If the
`role` is unset, it implies *default role* and full pipeline access (see *Default Role*
section above).

### `MasterArbitrationUpdate` from client to server

- If this is the first `MasterArbitrationUpdate` message sent by the client:
  - If the election ID is already used by another client connection (belonging to the 
    same associated `role_id`), the server should terminate the stream by returning an
    `INVALID_ARGUMENT` error.
  - Otherwise, if the max number of clients supported by the server is exceeded,
    the server should terminate the stream by returning a `RESOURCE_EXHAUSTED`
    error.
  - Otherwise, the client is added to the server's client list.

- If the client is already registered with the server and sends a new
  `MasterArbitrationUpdate` message:
  - If the `device_id` does not match the current one, the server should terminate
    the stream by returning a `FAILED_PRECONDITION` error.
  - Otherwise, if the `role.id` matches the current one
    - If the `election_id` matches the current one, the server will accept 'role.config'
      (if it does not match current one) only if this client is the master.
    - Otherwise, if the new election id is already used by another client
      connection, the server should terminate the stream by returning an
      `INVALID_ARGUMENT` error.
    - Otherwise, the server updates the `election_id` for this client. If this makes
      the client the new master, the server will also accept the given 'role.config`.
  - Otherwise (i.e. `role.id` is different from current one), the server moves the 
    client to the new role, and processes the update as described above. The server
    accepts the given `role.config` only if the client becomes master for this
    role based on the given `election_id`.

### `MasterArbitrationUpdate` from server to client

- If the mastership changed following a `MasterArbitrationUpdate` client
  request, all existing clients for that role are sent a `MasterArbitrationUpdate`
  message by the server. The `device_id` must be set. The `role` and `election_id`
  fields must be set to reflect the master client's view. The `status` field code
  must be `OK` for the master, and `ALREADY_EXISTS` for all the slave clients.

- Otherwise, only the client which sent the request is notified, e.g. a new
  connection, or a change in `role` and/or `election_id`. The `device_id` must be
  set. The `role` and `election_id` fields must be set to reflect the master
  client's view. The `status` field code must be `OK` if this client is the master,
  and `ALREADY_EXISTS` if it is a slave.

### Packet-In

Only the master receives `PacketIn` messages. If there is no master (i.e. no
client connections), packets are dropped.

### Packet-Out

Only the master can send `PacketOut` messages. In all other cases, the message
is dropped.

### Write RPC

The server will only perform write requests from the master client (for a given
role based on `role_id` and `election_id` in the `WriteRequest`). If a slave tries
to issue a `Write`, error code `PERMISSION_DENIED` will be returned. If the client
is using a *default role* (i.e. unset `role` in `MasterArbitrationUpdate` request),
the `role_id` must be set to default(0), otherwise error code `INVALID_ARGUMENT`
will be returned.

The `WriteRequest` will also be validated against the role config corresponding to
the given `role_id`. If a given Write `update` fails this validation, error code
`PERMISSION_DENIED` will be returned for that update.

NOTE: All clients are trusted; we do not support the case where a client is using
an incorrect `role_id` and `election_id` in its `WriteRequest` messages.

NOTE: For the sake of debugging and testing, we accept `WriteRequest`
messages when there is no master (i.e. no client connections) and the
`role_id` and `election_id` fields are not set.

### Read RPC

Everyone can perform a `Read`, even clients who haven't opened the
bi-directional stream and advertised an election ID.

### SetForwardingPipelineConfig RPC

The server will only allow a master client to set the forwarding-pipelien config.
The scope of `ForwardingPipelineConfig` is the entire forwarding pipeline. If there
are multiple roles, the control plane needs to agree offline on which role will set
the forwarding pipeline config.

If the client is using a *default role* (i.e. unset `role` in `MasterArbitrationUpdate`
request), the `role_id` must be set to default(0), otherwise error code
`INVALID_ARGUMENT` will be returned.

### Handling of Role Modification

Modification of client role is allowed by passing an updated `Role` message.
When a client generates a new `MasterArbitrationUpdate` stream message:
- Modification of `Role.id` constitutes moving the client to the new role.
- Modification of `Role.config` is accepted only from the master client (based on
  the `election_id` passed). The slaves are expected to update their role as well
  (though they would still remain slaves); for example, this scenario would happen in
  a software upgrade of controller which includes a modification of its role.
