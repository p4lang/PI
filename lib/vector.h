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

#ifndef PI_TOOLKIT_VECTOR_H_
#define PI_TOOLKIT_VECTOR_H_

#include <stddef.h>

typedef struct vector_s vector_t;

vector_t *vector_create(size_t e_size, size_t init_capacity);

void vector_destroy(vector_t *v);

void vector_push_back(vector_t *v, void *e);

void *vector_at(const vector_t *v, size_t index);

void *vector_data(const vector_t *v);

size_t vector_size(vector_t *v);

void vector_remove(vector_t *v, size_t index);

void vector_remove_e(vector_t *v, void *e);

/* typedef int (*VectorCmpFn)(const void *e1, const void *e2); */
/* void *vector_search(vector_t *v, VectorCmpFn cmp_fn, size_t start_index); */

#endif  // PI_TOOLKIT_VECTOR_H_
