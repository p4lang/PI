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

#ifndef PI_SRC_P4INFO_P4INFO_ARRAY_H_
#define PI_SRC_P4INFO_P4INFO_ARRAY_H_

#include <stddef.h>

typedef void (*P4InfoFreeOneFn)(void *);

typedef struct p4info_array_s {
  size_t e_size;
  size_t size;
  void *data;
} p4info_array_t;

void p4info_array_create(p4info_array_t *v, size_t e_size, size_t size);

void p4info_array_destroy(p4info_array_t *v, P4InfoFreeOneFn free_fn);

void *p4info_array_at(const p4info_array_t *v, size_t index);

size_t p4info_array_size(const p4info_array_t *v);

#endif  // PI_SRC_P4INFO_P4INFO_ARRAY_H_
