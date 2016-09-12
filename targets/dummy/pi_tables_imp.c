/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "PI/pi.h"

#include <stdio.h>

pi_status_t _pi_table_entry_add(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                int overwrite,
                                pi_entry_handle_t *entry_handle) {
  (void)session_handle;
  (void)dev_tgt;
  (void)table_id;
  (void)match_key;
  (void)table_entry;
  (void)overwrite;
  (void)entry_handle;
  printf("_pi_table_entry_add\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_set(pi_session_handle_t session_handle,
                                         pi_dev_tgt_t dev_tgt,
                                         pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry) {
  (void)session_handle;
  (void)dev_tgt;
  (void)table_id;
  (void)table_entry;
  printf("_pi_table_default_action_set\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_get(pi_session_handle_t session_handle,
                                         pi_dev_id_t dev_id,
                                         pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry) {
  (void)session_handle;
  (void)dev_id;
  (void)table_id;
  (void)table_entry;
  printf("_pi_table_default_action_get\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_default_action_done(pi_session_handle_t session_handle,
                                          pi_table_entry_t *table_entry) {
  (void)session_handle;
  (void)table_entry;
  printf("_pi_table_default_action_done\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_delete(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                   pi_entry_handle_t entry_handle) {
  (void)session_handle;
  (void)dev_id;
  (void)table_id;
  (void)entry_handle;
  printf("_pi_table_entry_delete\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_modify(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                   pi_entry_handle_t entry_handle,
                                   const pi_table_entry_t *table_entry) {
  (void)session_handle;
  (void)dev_id;
  (void)table_id;
  (void)entry_handle;
  (void)table_entry;
  printf("_pi_table_entry_modify\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entries_fetch(pi_session_handle_t session_handle,
                                    pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res) {
  (void)session_handle;
  (void)dev_id;
  (void)table_id;
  (void)res;
  printf("_pi_table_fetch\n");
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entries_fetch_done(pi_session_handle_t session_handle,
                                         pi_table_fetch_res_t *res) {
  (void)session_handle;
  (void)res;
  printf("_pi_table_fetch_done\n");
  return PI_STATUS_SUCCESS;
}
