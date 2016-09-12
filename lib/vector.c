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

#include "vector.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct vector_s {
  size_t e_size;
  size_t size;
  size_t capacity;
  void *data;
};

vector_t *vector_create(size_t e_size, size_t init_capacity) {
  assert(e_size > 0);
  assert(init_capacity > 0);
  vector_t *v = malloc(sizeof(vector_t));
  v->e_size = e_size;
  v->size = 0;
  v->capacity = init_capacity;
  v->data = malloc(init_capacity * e_size);
  return v;
}

void vector_destroy(vector_t *v) {
  free(v->data);
  free(v);
}

static void vector_expand(vector_t *v) {
  v->capacity *= 2;
  v->data = realloc(v, v->capacity * v->e_size);
}

static void *access(const vector_t *v, size_t index) {
  return (char *)v->data + (index * v->e_size);
}

void vector_push_back(vector_t *v, void *e) {
  assert(v->size <= v->capacity);
  if (v->size == v->capacity) vector_expand(v);
  memcpy(access(v, v->size), e, v->e_size);
  v->size++;
}

void *vector_at(const vector_t *v, size_t index) {
  assert(index < v->size);
  return access(v, index);
}

void *vector_data(const vector_t *v) { return v->data; }

size_t vector_size(vector_t *v) { return v->size; }

void vector_remove(vector_t *v, size_t index) {
  assert(index < v->size);
  v->size--;
  if (index == v->size) return;
  memmove(access(v, index), access(v, index + 1),
          (v->size - index) * v->e_size);
}

void vector_remove_e(vector_t *v, void *e) {
  assert(e >= v->data);
  size_t index = (char *)e - (char *)v->data;
  vector_remove(v, index);
}
