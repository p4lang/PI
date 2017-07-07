/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Start server and bind to default address (0.0.0.0:50051)
void PIGrpcServerRun();
// Start server and bind to given address (eg. localhost:1234,
// 192.168.1.1:31416, [::1]:27182, etc.)
void PIGrpcServerRunAddr(const char *server_address);

// Wait for the server to shutdown. Note that some other thread must be
// responsible for shutting down the server for this call to ever return.
void PIGrpcServerWait();

// Shutdown server but waits for all RPCs to finish
void PIGrpcServerShutdown();

// Force-shutdown server with a deadline for all RPCs to finish
void PIGrpcServerForceShutdown(int deadline_seconds);

// Once server has been shutdown, cleanup allocated resources.
void PIGrpcServerCleanup();

#ifdef __cplusplus
}
#endif
