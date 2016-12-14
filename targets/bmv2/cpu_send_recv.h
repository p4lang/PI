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

#include <PI/pi.h>

#include <mutex>
#include <string>
#include <thread>
#include <vector>

typedef struct pcap pcap_t;

namespace pibmv2 {

class CpuSendRecv {
 public:
  CpuSendRecv();

  ~CpuSendRecv();

  void start();
  int add_device(const std::string &cpu_iface, pi_dev_id_t dev_id);
  int remove_device(pi_dev_id_t dev_id);

  int send_pkt(pi_dev_id_t dev_id, const char *pkt, size_t size);

 private:
  struct OneDevice {
    std::string cpu_iface;
    pi_dev_id_t dev_id;
    pcap_t *pcap;
    int fd;
  };

  void recv_loop();
  void recv_one(const OneDevice &device);

  fd_set fds;
  int max_fd{0};
  std::vector<OneDevice> devices{};
  std::thread recv_thread{};
  bool stop_recv_thread{false};
  mutable std::mutex mutex{};
};

}  // namespace pibmv2
