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

#include "p4info_name_map.h"

#include <Judy.h>

void p4info_name_map_add(p4info_name_map_t *map, const char *name,
                         pi_p4_id_t id) {
  Word_t *ptr = NULL;
  JSLI(ptr, *map, (const uint8_t *)name);
  *ptr = id;
}

pi_p4_id_t p4info_name_map_get(const p4info_name_map_t *map, const char *name) {
  Word_t *ptr = NULL;
  JSLG(ptr, *map, (const uint8_t *)name);
  if (!ptr) return PI_INVALID_ID;
  return *ptr;
}

void p4info_name_map_destroy(p4info_name_map_t *map) {
  Word_t Rc_word;
  JSLFA(Rc_word, *map);
}
