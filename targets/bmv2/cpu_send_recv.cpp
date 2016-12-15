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

#include "cpu_send_recv.h"

#include <PI/pi.h>
#include <PI/target/pi_imp.h>

#include <pcap/pcap.h>

#include <mutex>
#include <string>
#include <thread>

#include <cassert>

namespace pibmv2 {

CpuSendRecv::CpuSendRecv() {
  FD_ZERO(&fds);
}

CpuSendRecv::~CpuSendRecv() {
  {
    std::unique_lock<std::mutex> lock(mutex);
    stop_recv_thread = true;
  }
  recv_thread.join();
}

void
CpuSendRecv::start() {
  recv_thread = std::thread(&CpuSendRecv::recv_loop, this);
}

int
CpuSendRecv::add_device(const std::string &cpu_iface, pi_dev_id_t dev_id) {
  OneDevice device = {cpu_iface, dev_id, nullptr, -1};

  char errbuf[PCAP_ERRBUF_SIZE];
  device.pcap = pcap_create(cpu_iface.c_str(), errbuf);

  if (!device.pcap) return -1;

  if (pcap_set_promisc(device.pcap, 1) != 0) {
    pcap_close(device.pcap);
    return -1;
  }

#ifdef WITH_PCAP_FIX
  if (pcap_set_timeout(device.pcap, 1) != 0) {
    pcap_close(device.pcap);
    return -1;
  }

  if (pcap_set_immediate_mode(device.pcap, 1) != 0) {
    pcap_close(device.pcap);
    return -1;
  }
#endif

  if (pcap_activate(device.pcap) != 0) {
    pcap_close(device.pcap);
    return -1;
  }

  device.fd = pcap_get_selectable_fd(device.pcap);
  if (device.fd < 0) {
    pcap_close(device.pcap);
    return -1;
  }

  // if (pcap_setnonblock(device.pcap, 1, errbuf) < 0) {
  //   pcap_close(device.pcap);
  //   return -1;
  // }

  std::unique_lock<std::mutex> lock(mutex);
  devices.push_back(std::move(device));
  if (device.fd > max_fd) max_fd = device.fd;
  FD_SET(device.fd, &fds);
  return 0;
}

int
CpuSendRecv::remove_device(pi_dev_id_t dev_id) {
  std::unique_lock<std::mutex> lock(mutex);
  auto it = devices.begin();
  for (; it != devices.end(); it++) {
    if (it->dev_id == dev_id) break;
  }
  if (it == devices.end()) return -1;
  FD_CLR(it->fd, &fds);
  devices.erase(it);
  return 0;
}

void
CpuSendRecv::recv_loop() {
  int n;
  fd_set current_fds;
  int current_max_fd;

  struct timeval timeout;
  while (1) {
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;

    {
      std::unique_lock<std::mutex> lock(mutex);
      current_fds = fds;
      current_max_fd = max_fd;
    }

    n = select(current_max_fd + 1, &current_fds, NULL, NULL, &timeout);
    assert(n >= 0 || errno == EINTR);

    {
      std::unique_lock<std::mutex> lock(mutex);
      if (stop_recv_thread) return;

      if (n <= 0) continue;

      for (const auto &device : devices) {
        if (n == 0) break;
        if (FD_ISSET(device.fd, &current_fds)) {
          --n;
          recv_one(device);
        }
      }
    }
  }
}

void
CpuSendRecv::recv_one(const OneDevice &device) {
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt_data;

  if (pcap_next_ex(device.pcap, &pkt_header, &pkt_data) != 1) {
    return;
  }

  if (pkt_header->caplen != pkt_header->len) {
    return;
  }

  size_t size = static_cast<size_t>(pkt_header->len);
  const char *data = reinterpret_cast<const char *>(pkt_data);
  pi_status_t pi_status = pi_packetin_receive(device.dev_id, data, size);
  (void)pi_status;
}

int
CpuSendRecv::send_pkt(pi_dev_id_t dev_id, const char *pkt, size_t size) {
  for (const auto &device : devices) {
    if (device.dev_id == dev_id) {
      return pcap_sendpacket(device.pcap,
                             reinterpret_cast<const unsigned char *>(pkt),
                             static_cast<int>(size));
    }
  }
  return -2;
}

}  // namespace pibmv2
