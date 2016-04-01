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

#ifndef PI_BMV2_CONN_MGR_H_
#define PI_BMV2_CONN_MGR_H_

#include <mutex>

#include <bm_sim/Standard.h>
#include <bm_sim/SimplePreLAG.h>
#include <bm_sim/SimpleSwitch.h>

using namespace  ::bm_runtime::standard;
using namespace  ::bm_runtime::simple_pre_lag;
using namespace  ::sswitch_runtime;

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

#endif  // PI_BMV2_CONN_MGR_H_
