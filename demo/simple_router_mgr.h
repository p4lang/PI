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

#include <PI/pi.h>
#include <PI/frontends/cpp/tables.h>

#include <boost/asio.hpp>

#include <iostream>
#include <cstring>
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>

struct __attribute__((packed)) cpu_header_t {
  char zeros[8];
  uint16_t reason;
  uint16_t port;
};

struct __attribute__((packed)) arp_header_t {
  uint16_t hw_type;
  uint16_t proto_type;
  uint8_t hw_addr_len;
  uint8_t proto_addr_len;
  uint16_t opcode;
  unsigned char hw_src_addr[6];
  uint32_t proto_src_addr;
  unsigned char hw_dst_addr[6];
  uint32_t proto_dst_addr;
};

struct __attribute__((packed)) eth_header_t {
  unsigned char dst_addr[6];
  unsigned char src_addr[6];
  uint16_t ethertype;
};

struct __attribute__((packed)) ipv4_header_t {
  unsigned char noise[16];
  uint32_t dst_addr;
};

class SimpleRouterMgr {
 public:
  friend class PacketHandler;
  friend class CounterQueryHandler;
  friend class ConfigUpdateHandler;

  typedef std::vector<char> Packet;

  SimpleRouterMgr(pi_dev_tgt_t dev_tgt, pi_p4info_t *p4info,
                  boost::asio::io_service &io_service);

  ~SimpleRouterMgr();

  int add_route(uint32_t prefix, int pLen, uint32_t nhop, uint16_t port,
                pi_entry_handle_t *handle);

  int set_default_entries();
  int static_config();

  void add_iface(uint16_t port_num, uint32_t ip_addr,
                 const unsigned char (&mac_addr)[6]);

  int query_counter(const std::string &counter_name, size_t index,
                    uint64_t *packets, uint64_t *bytes);

  int update_config(const std::string &config_buffer);

  void start_processing_packets();

  template <typename E> void post_event(E &&event) {
    io_service.post(std::move(event));
  }

 private:
  struct Iface {
    uint16_t port_num;
    uint32_t ip_addr;
    unsigned char mac_addr[6];
    pi_entry_handle_t h;

    static Iface make(uint16_t port_num, uint32_t ip_addr,
                      const unsigned char (&mac_addr)[6]) {
      Iface iface;
      iface.port_num = port_num;
      iface.ip_addr = ip_addr;
      memcpy(iface.mac_addr, mac_addr, sizeof(mac_addr));
      iface.h = 0;
      return iface;
    }
  };

  enum class UpdateMode {
    CONTROLLER_STATE,
    DEVICE_STATE
  };

  typedef std::vector<Packet> PacketQueue;

  void handle_arp(const arp_header_t &arp_header);
  void handle_ip(Packet &&pkt_copy, uint32_t dst_addr);

  int assign_mac_addr(uint16_t port, const unsigned char (&mac_addr)[6],
                      pi_entry_handle_t *handle);
  int add_arp_entry(uint32_t addr, const unsigned char (&mac_addr)[6],
                    pi_entry_handle_t *handle);
  void handle_arp_request(const arp_header_t &arp_header);
  void handle_arp_reply(const arp_header_t &arp_header);
  void send_arp_request(uint16_t port, uint32_t dst_addr);

  int add_route_(uint32_t prefix, int pLen, uint32_t nhop, uint16_t port,
                 pi_entry_handle_t *handle, UpdateMode udpate_mode);

  void add_iface_(uint16_t port_num, uint32_t ip_addr,
                  const unsigned char (&mac_addr)[6], UpdateMode update_mode);

  int static_config_(UpdateMode update_mode);

  int query_counter_(const std::string &counter_name, size_t index,
                     pi_counter_data_t *counter_data);

  int update_config_(const std::string &config_buffer);

  std::vector<Iface> ifaces;
  std::unordered_map<uint32_t, uint16_t> next_hops;
  std::unordered_map<uint32_t, PacketQueue> packet_queues;
  pi_dev_tgt_t dev_tgt;
  pi_p4info_t *p4info{nullptr};
  pi_session_handle_t sess;
  boost::asio::io_service &io_service;
};
