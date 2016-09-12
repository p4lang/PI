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

#include <PI/target/pi_learn_imp.h>

#include <stdio.h>

pi_status_t _pi_learn_msg_ack(pi_session_handle_t session_handle,
                              pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                              pi_learn_msg_id_t msg_id) {
  (void)session_handle;
  (void)dev_id;
  (void)learn_id;
  (void)msg_id;
  printf("%s\n", __func__);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_learn_msg_done(pi_learn_msg_t *msg) {
  (void)msg;
  printf("%s\n", __func__);
  return PI_STATUS_SUCCESS;
}
