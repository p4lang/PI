/* Copyright 2018-present Barefoot Networks, Inc.
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

//! @file

#ifndef PI_INC_PI_PI_MC_H_
#define PI_INC_PI_PI_MC_H_

#include <PI/pi_base.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t pi_mc_session_handle_t;
typedef uint32_t pi_mc_grp_id_t;
typedef uint32_t pi_mc_grp_handle_t;
typedef uint32_t pi_mc_node_handle_t;
typedef pi_port_t pi_mc_port_t;
typedef int32_t pi_mc_rid_t;

//! Init a client session for multicast.
pi_status_t pi_mc_session_init(pi_mc_session_handle_t *session_handle);

//! Terminate a client session for multicast.
pi_status_t pi_mc_session_cleanup(pi_mc_session_handle_t session_handle);

pi_status_t pi_mc_grp_create(pi_mc_session_handle_t session_handle,
                             pi_dev_id_t dev_id, pi_mc_grp_id_t grp_id,
                             pi_mc_grp_handle_t *grp_handle);

pi_status_t pi_mc_grp_delete(pi_mc_session_handle_t session_handle,
                             pi_dev_id_t dev_id, pi_mc_grp_handle_t grp_handle);

pi_status_t pi_mc_node_create(pi_mc_session_handle_t session_handle,
                              pi_dev_id_t dev_id, pi_mc_rid_t rid,
                              size_t eg_ports_count,
                              const pi_mc_port_t *eg_ports,
                              pi_mc_node_handle_t *node_handle);

pi_status_t pi_mc_node_modify(pi_mc_session_handle_t session_handle,
                              pi_dev_id_t dev_id,
                              pi_mc_node_handle_t node_handle,
                              size_t eg_ports_count,
                              const pi_mc_port_t *eg_ports);

pi_status_t pi_mc_node_delete(pi_mc_session_handle_t session_handle,
                              pi_dev_id_t dev_id,
                              pi_mc_node_handle_t node_handle);

pi_status_t pi_mc_grp_attach_node(pi_mc_session_handle_t session_handle,
                                  pi_dev_id_t dev_id,
                                  pi_mc_grp_handle_t grp_handle,
                                  pi_mc_node_handle_t node_handle);

pi_status_t pi_mc_grp_detach_node(pi_mc_session_handle_t session_handle,
                                  pi_dev_id_t dev_id,
                                  pi_mc_grp_handle_t grp_handle,
                                  pi_mc_node_handle_t node_handle);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_MC_H_
