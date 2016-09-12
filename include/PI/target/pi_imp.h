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

#ifndef PI_INC_PI_TARGET_PI_IMP_H_
#define PI_INC_PI_TARGET_PI_IMP_H_

#include "PI/pi.h"

#ifdef __cplusplus
extern "C" {
#endif

pi_status_t _pi_init(void *extra);

pi_status_t _pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *extra);

pi_status_t _pi_update_device_start(pi_dev_id_t dev_id,
                                    const pi_p4info_t *p4info,
                                    const char *device_data,
                                    size_t device_data_size);

pi_status_t _pi_update_device_end(pi_dev_id_t dev_id);

pi_status_t _pi_remove_device(pi_dev_id_t dev_id);

pi_status_t _pi_session_init(pi_session_handle_t *session_handle);

pi_status_t _pi_session_cleanup(pi_session_handle_t session_handle);

pi_status_t _pi_destroy();

pi_status_t _pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                               size_t size);

pi_status_t pi_packetin_receive(pi_dev_id_t dev_id, const char *pkt,
                                size_t size);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_TARGET_PI_IMP_H_
