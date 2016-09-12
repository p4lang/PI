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

#ifndef PI_BMV2_CONN_MGR_H_
#define PI_BMV2_CONN_MGR_H_

#include <bm/Standard.h>
#include <bm/SimplePreLAG.h>
#include <bm/SimpleSwitch.h>

#include <mutex>

using namespace ::bm_runtime::standard;        // NOLINT(build/namespaces)
using namespace ::bm_runtime::simple_pre_lag;  // NOLINT(build/namespaces)
using namespace ::sswitch_runtime;             // NOLINT(build/namespaces)

namespace pibmv2 {

struct Client {
  StandardClient *c;
  std::unique_lock<std::mutex> _lock;
};

struct McClient {
  SimplePreLAGClient *c;
  std::unique_lock<std::mutex> _lock;
};

struct SSwitchClient {
  SimpleSwitchClient *c;
  std::unique_lock<std::mutex> _lock;
};

struct conn_mgr_t;

conn_mgr_t *conn_mgr_create();
void conn_mgr_destroy(conn_mgr_t *conn_mgr_state);

Client conn_mgr_client(conn_mgr_t *, int dev_id);
McClient conn_mgr_mc_client(conn_mgr_t *, int dev_id);
SSwitchClient conn_mgr_sswitch_client(conn_mgr_t *, int dev_id);

int conn_mgr_client_init(conn_mgr_t *, int dev_id, int thrift_port_num);
int conn_mgr_client_close(conn_mgr_t *, int dev_id);

}  // namespace pibmv2

#endif  // PI_BMV2_CONN_MGR_H_
