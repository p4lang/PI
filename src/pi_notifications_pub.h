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

#ifndef PI_SRC_PI_NOTIFICATIONS_PUB_H_
#define PI_SRC_PI_NOTIFICATIONS_PUB_H_

#include <PI/pi_learn.h>

pi_status_t pi_notifications_init(const char *notifications_addr);

void pi_notifications_pub_learn(const pi_learn_msg_t *msg);

void pi_notifications_pub_packetin(pi_dev_id_t dev_id, const char *pkt,
                                   size_t size);

#endif  // PI_SRC_PI_NOTIFICATIONS_PUB_H_
