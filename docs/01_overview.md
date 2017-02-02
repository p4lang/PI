# Overview

Protocol Independent API (PI or P4 Runtime) defines a set of APIs that
allow interacting with entities defined in a P4 program. These
include: tables, counters, meters ...

PI APIs are defined at the level of properties that can be
effected. Examples include adding and deleting table entries. They are
independent from the actual instance of the controlled object (and
thus the name) which is passed as a parameter to the API.
