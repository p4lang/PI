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

#pragma once

#include <string>
#include <mutex>

struct MHD_Daemon;

class SimpleRouterMgr;

class WebServer {
 public:
  WebServer(SimpleRouterMgr *simple_router_mgr, int port = 8888);
  ~WebServer();

  void set_json_name(const std::string &json_name);
  std::string get_json_name() const;

  int query_counter(const std::string &counter_name, size_t index,
                    uint64_t *packets, uint64_t *bytes);

  int update_json_config(const std::string &config_buffer);

  int start();

 private:
  SimpleRouterMgr *simple_router_mgr{nullptr};
  int port;
  std::string current_json{""};
  struct MHD_Daemon *daemon{NULL};
  mutable std::mutex mutex;
};
