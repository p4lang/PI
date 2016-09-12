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

#include <bm/pdfixed/pd_static.h>

#include <pd/pd.h>

#include <stdio.h>

#define DEVICE_THRIFT_PORT 9090

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "P4 native JSON configuration needed.\n");
    fprintf(stderr, "Usage: %s <path to config>\n", argv[0]);
    return 1;
  }

  p4_pd_init();

  p4_pd_dev_target_t dev_tgt = {0, 0xFF};
  p4_pd_entry_hdl_t entry_hdl;

  p4_pd_test_init();

  pd_assign_extra_t extras[2];
  memset(extras, 0, sizeof(extras));
  char port_str[16];
  sprintf(port_str, "%d", DEVICE_THRIFT_PORT);
  extras[0].key = "port";
  extras[0].v = port_str;
  extras[1].end_of_extras = 1;

  p4_pd_test_assign_device(dev_tgt.device_id, argv[1], extras);

  p4_pd_sess_hdl_t sess_hdl;
  p4_pd_client_init(&sess_hdl);
  printf("Session handle is %d\n", sess_hdl);

  p4_pd_test_actionA_action_spec_t actionA_action_spec = {0xaa, 0xbb, 0xcc,
                                                          0xdd, 0xee, 0xff};
  p4_pd_test_actionB_action_spec_t actionB_action_spec = {0xab};
  // right now PD assumes everything is passed in network byte order, so this
  // will actually be interpreted as byte string "bb00aa00"
  p4_pd_test_ExactOne_match_spec_t ExactOne_match_spec = {0x00aa00bb};
  p4_pd_test_ExactOne_table_add_with_actionA(sess_hdl, dev_tgt,
                                             &ExactOne_match_spec,
                                             &actionA_action_spec, &entry_hdl);

  p4_pd_test_ExactOne_table_modify_with_actionB(
      sess_hdl, dev_tgt.device_id, entry_hdl, &actionB_action_spec);

  p4_pd_test_ExactOne_table_delete(sess_hdl, dev_tgt.device_id, entry_hdl);

  p4_pd_test_remove_device(dev_tgt.device_id);
  p4_pd_client_cleanup(sess_hdl);
  p4_pd_cleanup();
}
