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

#include <PI/int/serialize.h>
#include <PI/int/rpc_common.h>

#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>

#include <string.h>

#include "pi_notifications_pub.h"

static char *addr = NULL;
static int pub_socket = 0;

static size_t emit_notifications_topic(char *dst, const char *topic) {
  memcpy(dst, topic, sizeof(s_pi_notifications_topic_t));
  return sizeof(s_pi_notifications_topic_t);
}

static size_t learn_msg_size(const pi_learn_msg_t *msg) {
  size_t s = 0;
  s += sizeof(s_pi_learn_msg_hdr_t);
  s += msg->num_entries * msg->entry_size;
  return s;
}

static size_t emit_learn_msg(char *dst, const pi_learn_msg_t *msg) {
  size_t s = 0;
  s += emit_notifications_topic(dst + s, "PILEA|");
  s += emit_dev_tgt(dst + s, msg->dev_tgt);
  s += emit_p4_id(dst + s, msg->learn_id);
  s += emit_learn_msg_id(dst + s, msg->msg_id);
  s += emit_uint32(dst + s, msg->num_entries);
  s += emit_uint32(dst + s, msg->entry_size);
  memcpy(dst + s, msg->entries, msg->num_entries * msg->entry_size);
  return s;
}

static void pub_notification(char *msg, size_t msg_size) {
  int bytes_sent = nn_send(pub_socket, &msg, NN_MSG, 0);
  assert((size_t)bytes_sent == msg_size);
}

void pi_notifications_pub_learn(const pi_learn_msg_t *msg) {
  size_t pub_msg_size = learn_msg_size(msg);
  char *pub_msg = nn_allocmsg(pub_msg_size, 0);
  emit_learn_msg(pub_msg, msg);
  pub_notification(pub_msg, pub_msg_size);
}

void pi_notifications_pub_packetin(pi_dev_id_t dev_id, const char *pkt,
                                   size_t size) {
  size_t pub_msg_size = sizeof(s_pi_notifications_topic_t);
  pub_msg_size += sizeof(s_pi_dev_id_t);
  pub_msg_size += sizeof(uint32_t);
  pub_msg_size += size;
  char *pub_msg = nn_allocmsg(pub_msg_size, 0);

  char *msg = pub_msg;
  msg += emit_notifications_topic(msg, "PIPKT|");
  msg += emit_dev_id(msg, dev_id);
  msg += emit_uint32(msg, size);
  memcpy(msg, pkt, size);
  pub_notification(pub_msg, pub_msg_size);
}

pi_status_t pi_notifications_init(const char *notifications_addr) {
  assert(notifications_addr);
  addr = strdup(notifications_addr);
  pub_socket = nn_socket(AF_SP, NN_PUB);
  assert(pub_socket >= 0);
  if (nn_bind(pub_socket, addr) < 0) return PI_STATUS_NOTIF_BIND_ERROR;
  return PI_STATUS_SUCCESS;
}
