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

#ifndef PI_INC_PI_TARGET_PI_LEARN_IMP_H_
#define PI_INC_PI_TARGET_PI_LEARN_IMP_H_

#include <PI/pi_learn.h>

#ifdef __cplusplus
extern "C" {
#endif

pi_status_t pi_learn_new_msg(pi_learn_msg_t *msg);

pi_status_t _pi_learn_msg_ack(pi_session_handle_t session_handle,
                              pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                              pi_learn_msg_id_t msg_id);

pi_status_t _pi_learn_msg_done(pi_learn_msg_t *msg);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_TARGET_PI_LEARN_IMP_H_
