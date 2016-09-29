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

#include "simple_router_mgr.h"

#include <arpa/inet.h>

// #include <functional>
#include <boost/bind.hpp>

#include <future>

#define CPU_PORT static_cast<uint16_t>(64)

namespace {

enum CPU_REASON {
  NO_ARP_ENTRY = 0,
  ARP_MSG = 1,
  DATA_PKT = 2,
};

size_t set_cpu_header(cpu_header_t *cpu_header, uint16_t reason,
                      uint16_t port) {
  memset(cpu_header->zeros, 0, sizeof(cpu_header->zeros));
  cpu_header->reason = htons(reason);
  cpu_header->port = htons(port);
  return sizeof(*cpu_header);
}

size_t set_eth_header(eth_header_t *eth_header,
                      const unsigned char (&dst_addr)[6],
                      const unsigned char (&src_addr)[6],
                      uint16_t ethertype) {
  memcpy(eth_header->dst_addr, dst_addr, sizeof(dst_addr));
  memcpy(eth_header->src_addr, src_addr, sizeof(src_addr));
  eth_header->ethertype = htons(ethertype);
  return sizeof(*eth_header);
}

size_t set_arp_header(arp_header_t *arp_rep, uint16_t opcode,
                      const unsigned char (&hw_src_addr)[6],
                      uint32_t proto_src_addr,
                      const unsigned char (&hw_dst_addr)[6],
                      uint32_t proto_dst_addr) {
  arp_rep->hw_type = 1;
  arp_rep->hw_type = htons(arp_rep->hw_type);
  arp_rep->proto_type = 0x800;
  arp_rep->proto_type = htons(arp_rep->proto_type);
  arp_rep->hw_addr_len = sizeof(hw_src_addr);
  arp_rep->proto_addr_len = sizeof(proto_src_addr);
  arp_rep->opcode = htons(opcode);
  memcpy(arp_rep->hw_src_addr, hw_src_addr, sizeof(hw_src_addr));
  arp_rep->proto_src_addr = htonl(proto_src_addr);
  memcpy(arp_rep->hw_dst_addr, hw_dst_addr, sizeof(hw_dst_addr));
  arp_rep->proto_dst_addr = htonl(proto_dst_addr);
  return sizeof(*arp_rep);
}

}  // namespace

struct MgrHandler {
  MgrHandler(SimpleRouterMgr *mgr)
      : simple_router_mgr(mgr) { }

  SimpleRouterMgr *simple_router_mgr;
};

struct PacketHandler : public MgrHandler {
  PacketHandler(SimpleRouterMgr *mgr, SimpleRouterMgr::Packet &&pkt_copy)
      : MgrHandler(mgr), pkt_copy(std::move(pkt_copy)) { }

  void operator()() {
    char *pkt = pkt_copy.data();
    size_t size = pkt_copy.size();
    size_t offset = 0;
    cpu_header_t cpu_hdr;
    if ((size - offset) < sizeof(cpu_hdr)) return;
    char zeros[8];
    memset(zeros, 0, sizeof(zeros));
    if (memcmp(zeros, pkt, sizeof(zeros))) return;
    memcpy(&cpu_hdr, pkt, sizeof(cpu_hdr));
    cpu_hdr.reason = ntohs(cpu_hdr.reason);
    cpu_hdr.port = ntohs(cpu_hdr.port);
    offset += sizeof(cpu_hdr);
    if ((size - offset) < sizeof(eth_header_t)) return;
    offset += sizeof(eth_header_t);
    if (cpu_hdr.reason == NO_ARP_ENTRY) {
      if ((size - offset) < sizeof(ipv4_header_t)) return;
      ipv4_header_t ip_hdr;
      memcpy(&ip_hdr, pkt + offset, sizeof(ip_hdr));
      ip_hdr.dst_addr = ntohl(ip_hdr.dst_addr);
      simple_router_mgr->handle_ip(std::move(pkt_copy), ip_hdr.dst_addr);
    } else if (cpu_hdr.reason == ARP_MSG) {
      if ((size - offset) < sizeof(arp_header_t)) return;
      arp_header_t arp_header;
      memcpy(&arp_header, pkt + offset, sizeof(arp_header));
      arp_header.hw_type = ntohs(arp_header.hw_type);
      arp_header.proto_type = ntohs(arp_header.proto_type);
      arp_header.opcode = ntohs(arp_header.opcode);
      arp_header.proto_src_addr = ntohl(arp_header.proto_src_addr);
      arp_header.proto_dst_addr = ntohl(arp_header.proto_dst_addr);
      simple_router_mgr->handle_arp(arp_header);
    }
  }

  SimpleRouterMgr::Packet pkt_copy;
};

struct CounterQueryHandler : public MgrHandler {
  CounterQueryHandler(SimpleRouterMgr *mgr,
                      const std::string &counter_name,
                      size_t index,
                      std::promise<pi_counter_data_t> &promise)
      : MgrHandler(mgr), counter_name(counter_name), index(index),
        promise(promise) { }

  void operator()() {
    pi_counter_data_t d;
    int rc = simple_router_mgr->query_counter_(counter_name, index, &d);
    if (rc) d.valid = 0;
    promise.set_value(d);
  }

  std::string counter_name;
  size_t index;
  std::promise<pi_counter_data_t> &promise;
};

struct ConfigUpdateHandler : public MgrHandler {
  ConfigUpdateHandler(SimpleRouterMgr *mgr,
                      const std::string &config_buffer,
                      std::promise<int> &promise)
      : MgrHandler(mgr), config_buffer(config_buffer), promise(promise) { }

  void operator()() {
    int rc = simple_router_mgr->update_config_(config_buffer);
    promise.set_value(rc);
  }

  const std::string &config_buffer;
  std::promise<int> &promise;
};

namespace {

void packetin_cb(pi_dev_id_t dev_id, const char *pkt, size_t size,
                 void *cookie) {
  SimpleRouterMgr::Packet pkt_copy(&pkt[0], &pkt[size]);
  SimpleRouterMgr *simple_router_mgr = static_cast<SimpleRouterMgr *>(cookie);
  simple_router_mgr->post_event(
      PacketHandler(simple_router_mgr, std::move(pkt_copy)));
}

}  // namespace

SimpleRouterMgr::SimpleRouterMgr(pi_dev_tgt_t dev_tgt, pi_p4info_t *p4info,
                                 boost::asio::io_service &io_service)
    : dev_tgt(dev_tgt), p4info(p4info), io_service(io_service) {
  pi_session_init(&sess);
}

SimpleRouterMgr::~SimpleRouterMgr() {
  pi_session_cleanup(sess);
}

int
SimpleRouterMgr::add_route_(uint32_t prefix, int pLen, uint32_t nhop,
                            uint16_t port, pi_entry_handle_t *handle,
                            UpdateMode update_mode) {
  pi::error_code_t rc = 0;

  if (update_mode == UpdateMode::DEVICE_STATE) {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "ipv4_lpm");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "set_nhop");

    // match key
    pi::MatchKey match_key(p4info, t_id);
    rc |= match_key.set_lpm(
        pi_p4info_field_id_from_name(p4info, "ipv4.dstAddr"), prefix, pLen);

    // action data
    pi::ActionData action_data(p4info, a_id);
    rc |= action_data.set_arg(
        pi_p4info_action_param_id_from_name(p4info, a_id, "nhop_ipv4"),
        nhop);
    rc |= action_data.set_arg(
        pi_p4info_action_param_id_from_name(p4info, a_id, "port"),
        port);

    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    rc |= mt.entry_add(match_key, action_data, true, handle);
  }

  if (update_mode == UpdateMode::CONTROLLER_STATE) {
    next_hops[nhop] = port;
  }

  return rc;
}

int
SimpleRouterMgr::add_route(uint32_t prefix, int pLen, uint32_t nhop,
                           uint16_t port, pi_entry_handle_t *handle) {
  int rc = 0;
  rc |= add_route_(prefix, pLen, nhop, port, handle,
                   UpdateMode::CONTROLLER_STATE);
  rc |= add_route_(prefix, pLen, nhop, port, handle, UpdateMode::DEVICE_STATE);
  return rc;
}

int
SimpleRouterMgr::add_arp_entry(uint32_t addr,
                               const unsigned char (&mac_addr)[6],
                               pi_entry_handle_t *handle) {
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "forward");
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "set_dmac");

  pi::error_code_t rc = 0;

  // match key
  pi::MatchKey match_key(p4info, t_id);
  rc |= match_key.set_exact(
      pi_p4info_field_id_from_name(p4info, "routing_metadata.nhop_ipv4"),
      addr);

  // action data
  pi::ActionData action_data(p4info, a_id);
  rc |= action_data.set_arg(
      pi_p4info_action_param_id_from_name(p4info, a_id, "dmac"),
      reinterpret_cast<const char *>(mac_addr), sizeof(mac_addr));

  pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
  rc |= mt.entry_add(match_key, action_data, true, handle);

  return rc;
}

int
SimpleRouterMgr::assign_mac_addr(uint16_t port,
                                 const unsigned char (&mac_addr)[6],
                                 pi_entry_handle_t *handle) {
  pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "send_frame");
  pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "rewrite_mac");

  pi::error_code_t rc = 0;

  // match key
  pi::MatchKey match_key(p4info, t_id);
  rc |= match_key.set_exact(
      pi_p4info_field_id_from_name(p4info, "standard_metadata.egress_port"),
      port);

  // action data
  pi::ActionData action_data(p4info, a_id);
  rc |= action_data.set_arg(
      pi_p4info_action_param_id_from_name(p4info, a_id, "smac"),
      reinterpret_cast<const char *>(mac_addr), sizeof(mac_addr));

  pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
  rc |= mt.entry_add(match_key, action_data, true, handle);

  return rc;
}

int
SimpleRouterMgr::set_default_entries() {
  pi::error_code_t rc = 0;

  {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "ipv4_lpm");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "_drop");
    pi::ActionData action_data(p4info, a_id);
    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    if (mt.default_entry_set(action_data) != PI_STATUS_SUCCESS)
      std::cout << "Error when adding default entry to 'ipv4_lpm'\n";
  }

  {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "forward");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "do_send_to_cpu");

    pi::ActionData action_data(p4info, a_id);
    rc |= action_data.set_arg(
        pi_p4info_action_param_id_from_name(p4info, a_id, "reason"),
        static_cast<uint16_t>(NO_ARP_ENTRY));
    rc |= action_data.set_arg(
        pi_p4info_action_param_id_from_name(p4info, a_id, "cpu_port"),
        CPU_PORT);
    assert(!rc);

    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    if (mt.default_entry_set(action_data) != PI_STATUS_SUCCESS)
      std::cout << "Error when adding default entry to 'forward'\n";
  }

  {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "forward");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "_drop");
    pi::MatchKey match_key(p4info, t_id);
    rc |= match_key.set_exact(
        pi_p4info_field_id_from_name(p4info, "routing_metadata.nhop_ipv4"),
        static_cast<uint32_t>(0));
    assert(!rc);
    pi::ActionData action_data(p4info, a_id);
    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    pi_entry_handle_t h;
    if (mt.entry_add(match_key, action_data, true, &h) != PI_STATUS_SUCCESS)
      std::cout << "Error when adding entry to 'forward'\n";
  }

  {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "send_frame");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "_drop");
    pi::ActionData action_data(p4info, a_id);
    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    if (mt.default_entry_set(action_data) != PI_STATUS_SUCCESS)
      std::cout << "Error when adding default entry to 'send_frame'\n";
  }

  {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "decap_cpu_header");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info,
                                                    "do_decap_cpu_header");
    pi::ActionData action_data(p4info, a_id);
    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    if (mt.default_entry_set(action_data) != PI_STATUS_SUCCESS)
      std::cout << "Error when adding default entry to 'decap_cpu_header'\n";
  }

  {
    pi_p4_id_t t_id = pi_p4info_table_id_from_name(p4info, "send_arp_to_cpu");
    pi_p4_id_t a_id = pi_p4info_action_id_from_name(p4info, "do_send_to_cpu");

    pi::ActionData action_data(p4info, a_id);
    rc |= action_data.set_arg(
        pi_p4info_action_param_id_from_name(p4info, a_id, "reason"),
        static_cast<uint16_t>(ARP_MSG));
    rc |= action_data.set_arg(
        pi_p4info_action_param_id_from_name(p4info, a_id, "cpu_port"),
        CPU_PORT);
    assert(!rc);

    pi::MatchTable mt(sess, dev_tgt, p4info, t_id);
    if (mt.default_entry_set(action_data) != PI_STATUS_SUCCESS)
      std::cout << "Error when adding default entry to 'send_arp_to_cpu'\n";
  }

  return rc;
}

int
SimpleRouterMgr::static_config_(UpdateMode update_mode) {
  pi_entry_handle_t route1_h, route2_h;
  add_route_(0x0a00000a, 32, 0x0a00000a, 1, &route1_h, update_mode);
  add_route_(0x0a00010a, 32, 0x0a00010a, 2, &route2_h, update_mode);
  {
    unsigned char hw1[6] = {0x00, 0xaa, 0xbb, 0x00, 0x00, 0x00};
    unsigned char hw2[6] = {0x00, 0xaa, 0xbb, 0x00, 0x00, 0x01};
    add_iface_(1, 0x0a000001, hw1, update_mode);
    add_iface_(2, 0x0a000101, hw2, update_mode);
  }
  return 0;
}

int
SimpleRouterMgr::static_config() {
  int rc = 0;
  rc |= static_config_(UpdateMode::CONTROLLER_STATE);
  rc |= static_config_(UpdateMode::DEVICE_STATE);
  return rc;
}

void
SimpleRouterMgr::handle_arp_request(const arp_header_t &arp_header) {
  for (const auto &iface : ifaces) {
    if (iface.ip_addr == arp_header.proto_dst_addr) {
      size_t rep_size = sizeof(cpu_header_t);
      rep_size += sizeof(eth_header_t);
      rep_size += sizeof(arp_header_t);
      std::unique_ptr<char []> rep(new char[rep_size]);
      size_t offset = 0;

      cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(rep.get());
      offset += set_cpu_header(cpu_header, ARP_MSG, iface.port_num);

      eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(
          rep.get() + offset);
      offset += set_eth_header(eth_header, arp_header.hw_src_addr,
                               iface.mac_addr, 0x0806);

      arp_header_t *arp_rep = reinterpret_cast<arp_header_t *>(
          rep.get() + offset);
      set_arp_header(arp_rep, 2, iface.mac_addr, iface.ip_addr,
                     arp_header.hw_src_addr, arp_header.proto_src_addr);

      std::cout << "Sending ARP reply\n";
      pi_packetout_send(dev_tgt.dev_id, rep.get(), rep_size);

      return;
    }
  }
}

void
SimpleRouterMgr::handle_arp_reply(const arp_header_t &arp_header) {
  uint32_t dst_addr = arp_header.proto_src_addr;
  pi_entry_handle_t h;
  add_arp_entry(dst_addr, arp_header.hw_src_addr, &h);
  auto it = packet_queues.find(dst_addr);
  if (it != packet_queues.end()) {
    for (auto &p : it->second) {
      size_t offset = 0;
      cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(p.data());
      offset += set_cpu_header(cpu_header, DATA_PKT, next_hops[dst_addr]);
      eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(
          p.data() + offset);
      memcpy(eth_header->dst_addr, arp_header.hw_src_addr,
             sizeof(eth_header->dst_addr));
      std::cout << "Reinjecting data packet\n";
      pi_packetout_send(dev_tgt.dev_id, p.data(), p.size());
    }
    packet_queues.erase(it);
  }
}

void
SimpleRouterMgr::handle_arp(const arp_header_t &arp_header) {
  switch (arp_header.opcode) {
    case 1:  // request
      std::cout << "Arp request\n";
      handle_arp_request(arp_header);
      break;
    case 2:  // reply
      std::cout << "Arp rep\n";
      handle_arp_reply(arp_header);
      break;
    default:
      assert(0);
  }
}

void
SimpleRouterMgr::send_arp_request(uint16_t port, uint32_t dst_addr) {
  for (const auto &iface : ifaces) {
    if (iface.port_num == port) {
      size_t rep_size = sizeof(cpu_header_t);
      rep_size += sizeof(eth_header_t);
      rep_size += sizeof(arp_header_t);
      std::unique_ptr<char []> rep(new char[rep_size]);
      size_t offset = 0;

      cpu_header_t *cpu_header = reinterpret_cast<cpu_header_t *>(rep.get());
      offset += set_cpu_header(cpu_header, ARP_MSG, port);

      unsigned char broadcast_addr[6];
      memset(broadcast_addr, 0xff, sizeof(broadcast_addr));
      eth_header_t *eth_header = reinterpret_cast<eth_header_t *>(
          rep.get() + offset);
      offset += set_eth_header(eth_header, broadcast_addr,
                               iface.mac_addr, 0x0806);

      arp_header_t *arp_rep = reinterpret_cast<arp_header_t *>(
          rep.get() + offset);
      set_arp_header(arp_rep, 1, iface.mac_addr, iface.ip_addr,
                     broadcast_addr, dst_addr);

      std::cout << "Sending ARP request\n";
      pi_packetout_send(dev_tgt.dev_id, rep.get(), rep_size);

      return;
    }
  }
}

void
SimpleRouterMgr::handle_ip(Packet &&pkt_copy, uint32_t dst_addr) {
  auto it = next_hops.find(dst_addr);
  if (it == next_hops.end()) return;
  // creates a queue if does not exist
  PacketQueue &queue = packet_queues[dst_addr];
  queue.push_back(std::move(pkt_copy));
  send_arp_request(it->second, dst_addr);
}

void
SimpleRouterMgr::add_iface_(uint16_t port_num, uint32_t ip_addr,
                            const unsigned char (&mac_addr)[6],
                            UpdateMode update_mode) {
  if (update_mode == UpdateMode::CONTROLLER_STATE)
    ifaces.push_back(Iface::make(port_num, ip_addr, mac_addr));
  if (update_mode == UpdateMode::DEVICE_STATE)
    assign_mac_addr(port_num, ifaces.back().mac_addr, &ifaces.back().h);
}

void
SimpleRouterMgr::add_iface(uint16_t port_num, uint32_t ip_addr,
                           const unsigned char (&mac_addr)[6]) {
  add_iface_(port_num, ip_addr, mac_addr, UpdateMode::CONTROLLER_STATE);
  add_iface_(port_num, ip_addr, mac_addr, UpdateMode::DEVICE_STATE);
}

int
SimpleRouterMgr::query_counter(const std::string &counter_name, size_t index,
                               uint64_t *packets, uint64_t *bytes) {
  std::promise<pi_counter_data_t> promise;
  auto future = promise.get_future();
  CounterQueryHandler h(this, counter_name, index, promise);
  post_event(std::move(h));
  future.wait();
  pi_counter_data_t counter_data = future.get();
  if (!counter_data.valid) return 1;
  if (counter_data.valid & PI_COUNTER_UNIT_PACKETS)
    *packets = counter_data.packets;
  else
    *packets = 0;
  if (counter_data.valid & PI_COUNTER_UNIT_BYTES)
    *bytes = counter_data.bytes;
  else
    *bytes = 0;
  return 0;
}

int
SimpleRouterMgr::query_counter_(const std::string &counter_name, size_t index,
                                pi_counter_data_t *counter_data) {
  pi_p4_id_t counter_id = pi_p4info_counter_id_from_name(p4info,
                                                         counter_name.c_str());
  if (counter_id == PI_INVALID_ID) {
    std::cout << "Trying to read unknown counter.\n";
    return 1;
  }
  pi_status_t status = pi_counter_read(sess, dev_tgt, counter_id, index,
                                       PI_COUNTER_FLAGS_NONE, counter_data);
  if (status != PI_STATUS_SUCCESS) {
    std::cout << "Error when trying to read counter (" << status << ")\n";
    return 1;
  }
  return 0;
}

int
SimpleRouterMgr::update_config(const std::string &config_buffer) {
  std::promise<int> promise;
  auto future = promise.get_future();
  ConfigUpdateHandler h(this, config_buffer, promise);
  post_event(std::move(h));
  future.wait();
  return future.get();
}

int
SimpleRouterMgr::update_config_(const std::string &config_buffer) {
  std::cout << "Updating config\n";
  pi_p4info_t *p4info_new;
  pi_add_config(config_buffer.c_str(), PI_CONFIG_TYPE_BMV2_JSON, &p4info_new);
  pi_p4info_t *p4info_prev = p4info;
  p4info = p4info_new;
  pi_destroy_config(p4info_prev);
  pi_status_t pi_status;
  pi_status = pi_update_device_start(dev_tgt.dev_id, p4info,
                                     config_buffer.c_str(),
                                     config_buffer.size());
  if (pi_status != PI_STATUS_SUCCESS) {
    std::cout << "Error when initiating config update\n";
    return 1;
  }
  set_default_entries();
  static_config_(UpdateMode::DEVICE_STATE);
  // controller state does not change here
  // static_config_(UpdateMode::CONTROLLER_STATE);
  pi_status = pi_update_device_end(dev_tgt.dev_id);
  if (pi_status != PI_STATUS_SUCCESS) {
    std::cout << "Error when completing config update\n";
    return 1;
  }
  return 0;
}

void
SimpleRouterMgr::start_processing_packets() {
  pi_packetin_register_cb(dev_tgt.dev_id, packetin_cb,
                          static_cast<void *>(this));
}
