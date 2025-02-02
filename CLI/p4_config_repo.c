/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas
 *
 */

#include "p4_config_repo.h"

#include <uthash.h>

typedef struct {
  p4_config_id_t id;
  pi_p4info_t *p4info;
  UT_hash_handle hh;
} p4_config_hash_t;

static p4_config_hash_t *repo = NULL;
static p4_config_id_t id_ctr = 0;

p4_config_id_t p4_config_add(pi_p4info_t *p4info) {
  p4_config_hash_t *config_hash;
  config_hash = malloc(sizeof(*config_hash));
  config_hash->id = id_ctr++;
  config_hash->p4info = p4info;
  HASH_ADD(hh, repo, id, sizeof(config_hash->id), config_hash);
  return config_hash->id;
}

pi_p4info_t *p4_config_get(p4_config_id_t id) {
  p4_config_hash_t *config_hash;
  HASH_FIND(hh, repo, &id, sizeof(id), config_hash);
  return (config_hash) ? config_hash->p4info : NULL;
}

pi_p4info_t *p4_config_get_first() {
  // hash map is sorted by insertion order
  return (repo) ? repo->p4info : NULL;
}

void p4_config_cleanup() {
  p4_config_hash_t *config_hash, *tmp;
  // deletion-safe iteration
  HASH_ITER(hh, repo, config_hash, tmp) {
    pi_destroy_config(config_hash->p4info);
    HASH_DEL(repo, config_hash);
    free(config_hash);
  }
}
