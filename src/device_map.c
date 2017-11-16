/* Copyright 2013-present Barefoot Networks, Inc.
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
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "device_map.h"

#include <assert.h>

#include <Judy.h>

// Judy JL map uses Word_t for keys. On 32-bit systems, Word_t is a 32-bit word,
// which means device ids in the high 64-bit range would not be supported.
// TODO(antonin): change implementation to support arbitary 64-bit device ids
// even on 32-bit systems.
#define CHECK_DEV_ID_RANGE(dev_id) \
  assert((sizeof(pi_dev_id_t) <= sizeof(Word_t)) || (dev_id <= (~(Word_t)1)));

void device_map_create(device_map_t *map) { map->_map = NULL; }

bool device_map_add(device_map_t *map, pi_dev_id_t dev_id, void *e) {
  CHECK_DEV_ID_RANGE(dev_id);
  Pvoid_t *jmap = (Pvoid_t *)&map->_map;
  PWord_t ePtr;
  Word_t id = (Word_t)dev_id;
  JLG(ePtr, *jmap, id);
  if (ePtr != NULL) return false;
  JLI(ePtr, *jmap, id);
  assert(ePtr != NULL);
  assert(*ePtr == (Word_t)0);
  *ePtr = (Word_t)e;
  return true;
}

bool device_map_remove(device_map_t *map, pi_dev_id_t dev_id) {
  CHECK_DEV_ID_RANGE(dev_id);
  Pvoid_t *jmap = (Pvoid_t *)&map->_map;
  int rc;
  Word_t id = (Word_t)dev_id;
  JLD(rc, *jmap, id);
  return (rc == 1);
}

bool device_map_exists(device_map_t *map, pi_dev_id_t dev_id) {
  CHECK_DEV_ID_RANGE(dev_id);
  Pvoid_t *jmap = (Pvoid_t *)&map->_map;
  PWord_t ePtr;
  Word_t id = (Word_t)dev_id;
  JLG(ePtr, *jmap, id);
  return (ePtr != NULL);
}

void *device_map_get(device_map_t *map, pi_dev_id_t dev_id) {
  CHECK_DEV_ID_RANGE(dev_id);
  Pvoid_t *jmap = (Pvoid_t *)&map->_map;
  PWord_t ePtr;
  Word_t id = (Word_t)dev_id;
  JLG(ePtr, *jmap, id);
  if (ePtr == NULL) return NULL;
  return (void *)*ePtr;
}

void device_map_for_each(device_map_t *map, DeviceMapApplyFn fn, void *cookie) {
  Pvoid_t *jmap = (Pvoid_t *)&map->_map;
  PWord_t ePtr;
  Word_t id = 0;
  JLF(ePtr, *jmap, id);
  while (ePtr != NULL) {
    fn((void *)*ePtr, cookie);
    JLN(ePtr, *jmap, id);
  }
}

size_t device_map_count(device_map_t *map) {
  Pvoid_t *jmap = (Pvoid_t *)&map->_map;
  Word_t count;
  JLC(count, *jmap, 0, -1);
  return (size_t)count;
}

void device_map_destroy(device_map_t *map) {
  Pvoid_t *jmap = (Pvoid_t *)&map->_map;
  Word_t bytes_freed;
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wsign-compare"
  JLFA(bytes_freed, *jmap);
#pragma GCC diagnostic pop
  (void)bytes_freed;
}
