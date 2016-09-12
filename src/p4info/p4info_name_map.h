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

#ifndef PI_SRC_P4INFO_P4INFO_NAME_MAP_H_
#define PI_SRC_P4INFO_P4INFO_NAME_MAP_H_

#include <PI/pi_base.h>

typedef void *p4info_name_map_t;

void p4info_name_map_add(p4info_name_map_t *map, const char *name,
                         pi_p4_id_t id);

pi_p4_id_t p4info_name_map_get(const p4info_name_map_t *map, const char *name);

void p4info_name_map_destroy(p4info_name_map_t *map);

#endif  // PI_SRC_P4INFO_P4INFO_NAME_MAP_H_
