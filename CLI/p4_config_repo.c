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

#include "p4_config_repo.h"

#include <Judy.h>

static Pvoid_t repo = (Pvoid_t)NULL;

p4_config_id_t p4_config_add(pi_p4info_t *p4info) {
  int Rc_int;
  Word_t index = 0;
  JLFE(Rc_int, repo, index);
  assert(Rc_int == 1);
  Word_t *p4info_ptr = NULL;
  JLI(p4info_ptr, repo, index);
  assert(p4info_ptr && *p4info_ptr == 0);
  *p4info_ptr = (Word_t)p4info;
  return index;
}

pi_p4info_t *p4_config_get(p4_config_id_t id) {
  Word_t *p4info_ptr = NULL;
  JLG(p4info_ptr, repo, (Word_t)id);
  if (!p4info_ptr) return NULL;
  return (pi_p4info_t *)*p4info_ptr;
}

pi_p4info_t *p4_config_get_first() {
  Word_t index = 0;
  Word_t *p4info_ptr = NULL;
  JLF(p4info_ptr, repo, index);
  if (!p4info_ptr) return NULL;
  return (pi_p4info_t *)*p4info_ptr;
}

void p4_config_cleanup() {
  Word_t index = 0;
  Word_t *p4info_ptr = NULL;
  JLF(p4info_ptr, repo, index);
  while (p4info_ptr) {
    pi_destroy_config((pi_p4info_t *)*p4info_ptr);
    JLN(p4info_ptr, repo, index);
  }
  Word_t cnt;
  JLFA(cnt, repo);
}
