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

#ifndef _P4_PD_H_
#define _P4_PD_H_

#include "pd_tables.h"
#include "pd_counters.h"
#include "pd_meters.h"

#ifdef __cplusplus
extern "C" {
#endif

p4_pd_status_t ${pd_prefix}init(void);

p4_pd_status_t ${pd_prefix}assign_device(int dev_id,
                                         const char *config_path);
                                         /* const pd_assign_extra_t *extra); */

p4_pd_status_t ${pd_prefix}remove_device(int dev_id);

#ifdef __cplusplus
}
#endif

#endif
