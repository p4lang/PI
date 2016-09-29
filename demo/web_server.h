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
