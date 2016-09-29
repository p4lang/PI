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
