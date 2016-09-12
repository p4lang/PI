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

#include "p4info_array.h"

#include <stdlib.h>
#include <assert.h>

void p4info_array_create(p4info_array_t *v, size_t e_size, size_t size) {
  assert(e_size > 0);
  v->e_size = e_size;
  v->size = size;
  v->data = calloc(size, e_size);
}

static void *access(const p4info_array_t *v, size_t index) {
  return (char *)v->data + (index * v->e_size);
}

void p4info_array_destroy(p4info_array_t *v, P4InfoFreeOneFn free_fn) {
  if (free_fn != NULL) {
    for (size_t index = 0; index < v->size; index++) {
      free_fn(access(v, index));
    }
  }
  free(v->data);
}

void *p4info_array_at(const p4info_array_t *v, size_t index) {
  assert(index < v->size);
  return access(v, index);
}

size_t p4info_array_size(const p4info_array_t *v) { return v->size; }
