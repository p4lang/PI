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

#include <PI/pi.h>

#include <thread>
#include <mutex>
#include <string>
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
