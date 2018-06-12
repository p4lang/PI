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

#include <PI/pi_mc.h>
#include <PI/target/pi_mc_imp.h>

#include <algorithm>  // for std::reverse
#include <iostream>
#include <string>

#include "common.h"
#include "conn_mgr.h"

namespace pibmv2 {

extern conn_mgr_t *conn_mgr_state;

}  // namespace pibmv2

namespace {

std::string convert_map(const pi_mc_port_t *eg_ports, size_t eg_ports_count) {
  std::string output;
  for (size_t i = 0; i < eg_ports_count; i++) {
    output.resize(eg_ports[i] + 1, '0');
    output[eg_ports[i]] = '1';
  }
  std::reverse(output.begin(), output.end());
  return output;
}

}  // namespace

extern "C" {

pi_status_t _pi_mc_session_init(pi_mc_session_handle_t *session_handle) {
  *session_handle = 0;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_session_cleanup(pi_mc_session_handle_t session_handle) {
  (void)session_handle;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_grp_create(pi_mc_session_handle_t session_handle,
                              pi_dev_id_t dev_id,
                              pi_mc_grp_id_t grp_id,
                              pi_mc_grp_handle_t *grp_handle) {
  (void) session_handle;

  auto mc_client = conn_mgr_mc_client(pibmv2::conn_mgr_state, dev_id);
  try {
    *grp_handle = mc_client.c->bm_mc_mgrp_create(0, grp_id);
  } catch (InvalidMcOperation &imo) {
    const char *what =
        _McOperationErrorCode_VALUES_TO_NAMES.find(imo.code)->second;
    std::cout << "Invalid multicast operation (" << imo.code << "): "
              << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + imo.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_grp_delete(pi_mc_session_handle_t session_handle,
                              pi_dev_id_t dev_id,
                              pi_mc_grp_handle_t grp_handle) {
  (void) session_handle;

  auto mc_client = conn_mgr_mc_client(pibmv2::conn_mgr_state, dev_id);
  try {
    mc_client.c->bm_mc_mgrp_destroy(0, grp_handle);
  } catch (InvalidMcOperation &imo) {
    const char *what =
        _McOperationErrorCode_VALUES_TO_NAMES.find(imo.code)->second;
    std::cout << "Invalid multicast operation (" << imo.code << "): "
              << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + imo.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_node_create(pi_mc_session_handle_t session_handle,
                               pi_dev_id_t dev_id,
                               pi_mc_rid_t rid,
                               size_t eg_ports_count,
                               const pi_mc_port_t *eg_ports,
                               pi_mc_node_handle_t *node_handle) {
  (void) session_handle;

  auto mc_client = conn_mgr_mc_client(pibmv2::conn_mgr_state, dev_id);
  try {
    *node_handle = mc_client.c->bm_mc_node_create(
        0, rid, convert_map(eg_ports, eg_ports_count), "");
  } catch (InvalidMcOperation &imo) {
    const char *what =
        _McOperationErrorCode_VALUES_TO_NAMES.find(imo.code)->second;
    std::cout << "Invalid multicast operation (" << imo.code << "): "
              << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + imo.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_node_modify(pi_mc_session_handle_t session_handle,
                               pi_dev_id_t dev_id,
                               pi_mc_node_handle_t node_handle,
                               size_t eg_ports_count,
                               const pi_mc_port_t *eg_ports) {
  (void) session_handle;

  auto mc_client = conn_mgr_mc_client(pibmv2::conn_mgr_state, dev_id);
  try {
    mc_client.c->bm_mc_node_update(
        0, node_handle, convert_map(eg_ports, eg_ports_count), "");
  } catch (InvalidMcOperation &imo) {
    const char *what =
        _McOperationErrorCode_VALUES_TO_NAMES.find(imo.code)->second;
    std::cout << "Invalid multicast operation (" << imo.code << "): "
              << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + imo.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_node_delete(pi_mc_session_handle_t session_handle,
                               pi_dev_id_t dev_id,
                               pi_mc_node_handle_t node_handle) {
  (void) session_handle;

  auto mc_client = conn_mgr_mc_client(pibmv2::conn_mgr_state, dev_id);
  try {
    mc_client.c->bm_mc_node_destroy(0, node_handle);
  } catch (InvalidMcOperation &imo) {
    const char *what =
        _McOperationErrorCode_VALUES_TO_NAMES.find(imo.code)->second;
    std::cout << "Invalid multicast operation (" << imo.code << "): "
              << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + imo.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_grp_attach_node(pi_mc_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_mc_grp_handle_t grp_handle,
                                   pi_mc_node_handle_t node_handle) {
  (void) session_handle;

  auto mc_client = conn_mgr_mc_client(pibmv2::conn_mgr_state, dev_id);
  try {
    mc_client.c->bm_mc_node_associate(0, grp_handle, node_handle);
  } catch (InvalidMcOperation &imo) {
    const char *what =
        _McOperationErrorCode_VALUES_TO_NAMES.find(imo.code)->second;
    std::cout << "Invalid multicast operation (" << imo.code << "): "
              << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + imo.code);
  }

  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_grp_detach_node(pi_mc_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_mc_grp_handle_t grp_handle,
                                   pi_mc_node_handle_t node_handle) {
  (void) session_handle;

  auto mc_client = conn_mgr_mc_client(pibmv2::conn_mgr_state, dev_id);
  try {
    mc_client.c->bm_mc_node_dissociate(0, grp_handle, node_handle);
  } catch (InvalidMcOperation &imo) {
    const char *what =
        _McOperationErrorCode_VALUES_TO_NAMES.find(imo.code)->second;
    std::cout << "Invalid multicast operation (" << imo.code << "): "
              << what << std::endl;
    return static_cast<pi_status_t>(PI_STATUS_TARGET_ERROR + imo.code);
  }

  return PI_STATUS_SUCCESS;
}

}
