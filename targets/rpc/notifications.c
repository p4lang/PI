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

#include <PI/int/rpc_common.h>
#include <PI/int/serialize.h>
#include <PI/target/pi_imp.h>
#include <PI/target/pi_learn_imp.h>

#include <pthread.h>

#include <nanomsg/nn.h>
#include <nanomsg/pubsub.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pi_rpc.h"

static char *addr = NULL;
static int pub_socket = 0;

static pthread_t receive_thread;

static void handle_LEA(char *msg) {
  pi_learn_msg_t *learn_msg;
  learn_msg = malloc(sizeof(*learn_msg));
  size_t s = 0;
  s += sizeof(s_pi_notifications_topic_t);
  s += retrieve_dev_tgt(msg + s, &learn_msg->dev_tgt);
  s += retrieve_p4_id(msg + s, &learn_msg->learn_id);
  s += retrieve_learn_msg_id(msg + s, &learn_msg->msg_id);
  uint32_t tmp32;
  s += retrieve_uint32(msg + s, &tmp32);
  learn_msg->num_entries = tmp32;
  s += retrieve_uint32(msg + s, &tmp32);
  learn_msg->entry_size = tmp32;

  // in theory I can just point to the NN msg and postpone free'ing the msg
  // (call to nn_freemsg). I will implement it if needed for performance.
  /* learn_msg->entries = msg + s; */
  size_t entries_size = learn_msg->num_entries * learn_msg->entry_size;
  learn_msg->entries = malloc(entries_size);
  memcpy(learn_msg->entries, msg + s, entries_size);

  pi_learn_new_msg(learn_msg);
}

static void handle_PKT(char *msg) {
  size_t s = 0;
  s += sizeof(s_pi_notifications_topic_t);
  pi_dev_id_t dev_id;
  s += retrieve_dev_id(msg + s, &dev_id);
  uint32_t msg_size;
  s += retrieve_uint32(msg + s, &msg_size);
  pi_packetin_receive(dev_id, msg + s, msg_size);
  // we free the msg right away, app can make copy in cb
  nn_freemsg(msg);
}

static void *receive_loop(void *arg) {
  (void)arg;
  while (1) {
    char *msg = NULL;
    if (nn_recv(pub_socket, &msg, NN_MSG, 0) <= 0) {
      continue;
    }

    if (!memcmp("PILEA|", msg, sizeof "PILEA|")) {
      /* printf("Received learning notification.\n"); */
      handle_LEA(msg);
      nn_freemsg(msg);
    } else if (!memcmp("PIPKT|", msg, sizeof "PIPKT|")) {
      /* printf("Received packet-in notification.\n"); */
      handle_PKT(msg);
    } else {
      printf("Unknow notification type\n");
      nn_freemsg(msg);
    }
  }
  return NULL;
}

pi_status_t notifications_start(const char *notifications_addr) {
  assert(notifications_addr);
  addr = strdup(notifications_addr);
  pub_socket = nn_socket(AF_SP, NN_SUB);
  assert(pub_socket >= 0);
  // subscribe to all notifications
  nn_setsockopt(pub_socket, NN_SUB, NN_SUB_SUBSCRIBE, "", 0);
  int rcv_timeout_ms = 200;
  nn_setsockopt(pub_socket, NN_SOL_SOCKET, NN_RCVTIMEO, &rcv_timeout_ms,
                sizeof(rcv_timeout_ms));
  if (nn_connect(pub_socket, addr) < 0) return PI_STATUS_NOTIF_CONNECT_ERROR;

  pthread_create(&receive_thread, NULL, receive_loop, NULL);
  /* pthread_detach(receive_thread); */

  return PI_STATUS_SUCCESS;
}
