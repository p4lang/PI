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

#include "mock_switch.h"

#include <gmock/gmock.h>

#include <boost/functional/hash.hpp>
#include <boost/optional.hpp>

#include <algorithm>  // std::copy, std::for_each
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "PI/frontends/proto/device_mgr.h"
#include "PI/int/pi_int.h"
#include "PI/int/serialize.h"
#include "PI/pi.h"
#include "PI/pi_mc.h"
#include "PI/target/pi_imp.h"
#include "PI/target/pi_learn_imp.h"
#include "PI/target/pi_tables_imp.h"

namespace pi {
namespace proto {
namespace testing {

namespace {

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

class DummyMatchKey {
  friend struct DummyMatchKeyHash;
 public:
  explicit DummyMatchKey(const pi_match_key_t *match_key)
      : priority(match_key->priority),
        mk(&match_key->data[0], &match_key->data[match_key->data_size]) { }

  bool operator==(const DummyMatchKey& other) const {
    return priority == other.priority && mk == other.mk;
  }

  bool operator!=(const DummyMatchKey& other) const {
    return !(*this == other);
  }

  size_t emit(char *dst) const {
    size_t s = 0;
    s += emit_uint32(dst, priority);
    std::copy(mk.begin(), mk.end(), dst + s);
    s += mk.size();
    return s;
  }

  void get_match_key(pi_match_key_t *match_key,
                     std::vector<char> *storage) const {
    *storage = mk;
    match_key->priority = priority;
    match_key->data_size = mk.size();
    match_key->data = storage->data();
  }

  size_t nbytes() const {
    return mk.size();
  }

  void set_priority(int priority) {
    this->priority = priority;
  }

 private:
  uint32_t priority;
  std::vector<char> mk;
};

struct DummyMatchKeyHash {
  std::size_t operator()(const DummyMatchKey& b) const {
    std::size_t seed = 0;
    boost::hash_combine(seed, b.priority);
    boost::hash_range(seed, b.mk.begin(), b.mk.end());
    return seed;
  }
};

class ActionData {
 public:
  // define default constuctor for DummyTableEntry below
  ActionData() { }
  explicit ActionData(const pi_action_data_t *action_data)
      : action_id(action_data->action_id),
        data(&action_data->data[0],
             &action_data->data[action_data->data_size]) { }

  size_t emit(char *dst) const {
    size_t s = 0;
    s += emit_p4_id(dst, action_id);
    s += emit_uint32(dst + s, data.size());
    std::copy(data.begin(), data.end(), dst + s);
    s += data.size();
    return s;
  }

 private:
  pi_p4_id_t action_id;
  std::vector<char> data;
};

// CRTP seems overkill here, since we only need to access one static method in
// the derived classes...
template <typename T, typename ConfigType>
class DummyResource {
 public:
  using config_type = ConfigType;

  template <typename I>
  pi_status_t read(I index, ConfigType *config) const {
    auto it = resources.find(static_cast<typename Resources::key_type>(index));
    if (it == resources.end())
      *config = T::get_default();
    else
      *config = it->second;
    return PI_STATUS_SUCCESS;
  }

  template <typename I>
  pi_status_t write(I index, const ConfigType *config) {
    resources[static_cast<typename Resources::key_type>(index)] = *config;
    return PI_STATUS_SUCCESS;
  }

 private:
  using Resources = std::unordered_map<uint64_t, ConfigType>;
  using key_type = typename Resources::key_type;
  static_assert(sizeof(key_type) >= sizeof(uint64_t),
                "Key cannot fit uint64");
  static_assert(sizeof(key_type) >= sizeof(pi_entry_handle_t),
                "Key cannot fit entry handle");

  Resources resources;
};

class DummyMeter : public DummyResource<DummyMeter, pi_meter_spec_t> {
 public:
  static constexpr pi_res_type_id_t direct_res_type = PI_DIRECT_METER_ID;

  static pi_meter_spec_t get_default() {
    return {0, 0, 0, 0, PI_METER_UNIT_DEFAULT, PI_METER_TYPE_DEFAULT};
  }
};

class DummyCounter : public DummyResource<DummyCounter, pi_counter_data_t> {
 public:
  static constexpr pi_res_type_id_t direct_res_type = PI_DIRECT_COUNTER_ID;

  static pi_counter_data_t get_default() {
    return {PI_COUNTER_UNIT_PACKETS | PI_COUNTER_UNIT_BYTES, 0u, 0u};
  }
};

class DummyTableEntry {
 public:
  explicit DummyTableEntry(const pi_table_entry_t *table_entry)
      : type(table_entry->entry_type) {
    switch (table_entry->entry_type) {
      case PI_ACTION_ENTRY_TYPE_DATA:
        ad = ActionData(table_entry->entry.action_data);
        break;
      case PI_ACTION_ENTRY_TYPE_INDIRECT:
        indirect_h = table_entry->entry.indirect_handle;
        break;
      default:
        assert(0);
    }
    const auto *properties = table_entry->entry_properties;
    if (properties &&
        pi_entry_properties_is_set(properties, PI_ENTRY_PROPERTY_TYPE_TTL)) {
      ttl_ns = properties->ttl_ns;
    }
  }

  size_t emit(char *dst) const {
    size_t s = 0;
    s += emit_action_entry_type(dst, type);
    switch (type) {
      case PI_ACTION_ENTRY_TYPE_NONE:
        break;
      case PI_ACTION_ENTRY_TYPE_DATA:
        s += ad.emit(dst + s);
        break;
      case PI_ACTION_ENTRY_TYPE_INDIRECT:
        s += emit_indirect_handle(dst + s, indirect_h);
        break;
    }
    s += emit_uint32(dst + s, 0);  // properties
    return s;
  }

  uint64_t get_ttl() const { return ttl_ns; }

 private:
  pi_action_entry_type_t type;
  // not bothering with a union here
  ActionData ad;
  pi_indirect_handle_t indirect_h;
  uint64_t ttl_ns{0};
};

class DummyTable {
 public:
  struct Entry {
    // NOLINTNEXTLINE
    Entry(DummyMatchKey &&mk, DummyTableEntry &&entry)
        : mk(mk), entry(entry) { }

    DummyMatchKey mk;
    DummyTableEntry entry;
  };

  DummyTable(pi_p4_id_t table_id, const pi_p4info_t *p4info)
      : table_id(table_id), p4info(p4info) { }

  void add_counter(pi_p4_id_t c_id, DummyCounter *counter) {
    counters[c_id] = counter;
  }

  void add_meter(pi_p4_id_t m_id, DummyMeter *meter) {
    meters[m_id] = meter;
  }

  pi_status_t entry_add(const pi_match_key_t *match_key,
                        const pi_table_entry_t *table_entry,
                        pi_entry_handle_t *entry_handle) {
    auto r = key_to_handle.emplace(DummyMatchKey(match_key), entry_counter);
    // TODO(antonin): we need a better error code for duplicate entry
    if (!r.second) return PI_STATUS_TARGET_ERROR;
    // An actual target would probably discard the priority for a non-ternary
    // table...
    DummyMatchKey dmk(match_key);
    if (!has_ternary_match()) dmk.set_priority(0);
    entries.emplace(
        entry_counter,
        Entry(std::move(dmk), DummyTableEntry(table_entry)));

    // direct resources
    // my original plan was to support them in DummyTableEntry, but because I
    // need to access the Dummy instances for the resources, it seems easier to
    // do it here.
    if (table_entry->direct_res_config) {
      auto *configs = table_entry->direct_res_config->configs;
      for (size_t i = 0; i < table_entry->direct_res_config->num_configs; i++) {
        pi_p4_id_t res_id = configs[i].res_id;
        if (pi_is_direct_counter_id(res_id)) {
          counters[res_id]->write(
              entry_counter,
              static_cast<const pi_counter_data_t *>(configs[i].config));
        } else if (pi_is_direct_meter_id(res_id)) {
          meters[res_id]->write(
              entry_counter,
              static_cast<const pi_meter_spec_t *>(configs[i].config));
        } else {
          assert(0 && "Unsupported direct resource id");
        }
      }
    }

    *entry_handle = entry_counter++;

    return PI_STATUS_SUCCESS;
  }

  pi_status_t default_action_set(const pi_table_entry_t *table_entry) {
    // boost::optional::emplace is only available in "recent" versions of boost
    // (>= 1.56.0); to avoid issues we use copy assignment
    // default_entry.emplace(table_entry);
    default_entry = DummyTableEntry(table_entry);
    return PI_STATUS_SUCCESS;
  }

  pi_status_t default_action_reset() {
    default_entry.reset();
    return PI_STATUS_SUCCESS;
  }

  // TOFO(antonin): implement
  // TODO(antonin): support const default actions, how?
  pi_status_t default_action_get(pi_table_entry_t *table_entry) {
    (void) table_entry;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t entry_delete_wkey(const pi_match_key_t *match_key) {
    auto it = key_to_handle.find(DummyMatchKey(match_key));
    if (it == key_to_handle.end()) return PI_STATUS_TARGET_ERROR;
    auto entry_handle = it->second;
    auto cnt = entries.erase(entry_handle);
    (void) cnt;
    assert(cnt == 1);
    key_to_handle.erase(it);
    return PI_STATUS_SUCCESS;
  }

  pi_status_t entry_modify_wkey(const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry) {
    auto it = key_to_handle.find(DummyMatchKey(match_key));
    if (it == key_to_handle.end()) return PI_STATUS_TARGET_ERROR;
    auto entry_handle = it->second;
    auto &entry = entries.at(entry_handle);
    entry.entry = DummyTableEntry(table_entry);
    return PI_STATUS_SUCCESS;
  }

  pi_status_t entries_fetch(pi_table_fetch_res_t *res) {
    res->num_entries = entries.size();
    // TODO(antonin): it does not make much sense to me anymore for it to be the
    // target's responsibility to populate this field
    res->mkey_nbytes = 0;
    char *buf = new char[16384];  // should be large enough for testing
    char *buf_ptr = buf;
    for (const auto &p : entries) {
      buf_ptr += emit_entry_handle(buf_ptr, p.first);
      res->mkey_nbytes = p.second.mk.nbytes();
      buf_ptr += p.second.mk.emit(buf_ptr);
      buf_ptr += p.second.entry.emit(buf_ptr);
      buf_ptr += emit_direct_configs(buf_ptr, p.first);
    }
    res->entries = buf;
    res->entries_size = std::distance(buf, buf_ptr);
    return PI_STATUS_SUCCESS;
  }

  pi_status_t idle_timeout_config_set(const pi_idle_timeout_config_t *config) {
    idle_timeout_config = *config;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t entry_get_remaining_ttl(pi_entry_handle_t entry_handle,
                                      uint64_t *ttl_ns) {
    auto it = entries.find(entry_handle);
    if (it == entries.end()) return PI_STATUS_TARGET_ERROR;
    // we do not do any "real" ageing, we always return the initial TTL value
    *ttl_ns = it->second.entry.get_ttl();
    return PI_STATUS_SUCCESS;
  }

  pi_status_t entry_age(pi_dev_id_t dev_id,  // required to generate notif
                        pi_entry_handle_t entry_handle) const {
    auto it = entries.find(entry_handle);
    if (it == entries.end()) return PI_STATUS_TARGET_ERROR;
    std::vector<char> match_key_data;
    pi_match_key_t match_key;
    match_key.p4info = nullptr;
    match_key.table_id = table_id;
    it->second.mk.get_match_key(&match_key, &match_key_data);
    return pi_table_idle_timeout_notify(
        dev_id, table_id, &match_key, entry_handle);
  }

 private:
  bool has_ternary_match() const {
    size_t num_mfs = pi_p4info_table_num_match_fields(p4info, table_id);
    for (size_t idx = 0; idx < num_mfs; idx++) {
      auto mf_info = pi_p4info_table_match_field_info(p4info, table_id, idx);
      if (mf_info->match_type == PI_P4INFO_MATCH_TYPE_TERNARY ||
          mf_info->match_type == PI_P4INFO_MATCH_TYPE_RANGE)
        return true;
    }
    return false;
  }

  template <typename T, typename It>
  size_t emit_direct_resources_one_type(char *dst, pi_entry_handle_t h,
                                        const It first, const It last) const {
    size_t s = 0;
    PIDirectResMsgSizeFn msg_size_fn;
    PIDirectResEmitFn emit_fn;
    pi_direct_res_get_fns(
        T::direct_res_type, &msg_size_fn, &emit_fn, NULL, NULL);
    for (auto it = first; it != last; ++it) {
      s += emit_p4_id(dst + s, it->first);
      typename T::config_type config;
      it->second->read(h, &config);
      s += emit_uint32(dst + s, msg_size_fn(&config));
      s += emit_fn(dst + s, &config);
    }
    return s;
  }

  size_t emit_direct_configs(char *dst, pi_entry_handle_t h) const {
    size_t s = 0;
    s += emit_uint32(dst, counters.size() + meters.size());
    s += emit_direct_resources_one_type<DummyCounter>(
        dst + s, h, counters.begin(), counters.end());
    s += emit_direct_resources_one_type<DummyMeter>(
        dst + s, h, meters.begin(), meters.end());
    return s;
  }

  const pi_p4_id_t table_id;
  const pi_p4info_t *p4info;
  std::unordered_map<pi_entry_handle_t, Entry> entries{};
  std::unordered_map<DummyMatchKey, pi_entry_handle_t, DummyMatchKeyHash>
  key_to_handle{};
  boost::optional<DummyTableEntry> default_entry;
  size_t entry_counter{0};
  std::map<pi_p4_id_t, DummyCounter *> counters{};
  std::map<pi_p4_id_t, DummyMeter *> meters{};
  pi_idle_timeout_config_t idle_timeout_config{{}};  // zero-initialize
};

class DummyActionProf {
 public:
  pi_status_t member_create(const pi_action_data_t *action_data,
                            pi_indirect_handle_t *mbr_handle) {
    members.emplace(member_counter, ActionData(action_data));
    *mbr_handle = member_counter++;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t member_modify(pi_indirect_handle_t mbr_handle,
                            const pi_action_data_t *action_data) {
    auto it = members.find(mbr_handle);
    if (it == members.end()) return PI_STATUS_TARGET_ERROR;
    it->second = ActionData(action_data);
    return PI_STATUS_SUCCESS;
  }

  pi_status_t member_delete(pi_indirect_handle_t mbr_handle) {
    auto count = members.erase(mbr_handle);
    return (count == 0) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

  pi_status_t group_create(size_t max_size, pi_indirect_handle_t *grp_handle) {
    (void) max_size;
    groups.emplace(group_counter, GroupMembers());
    *grp_handle = group_counter++;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t group_delete(pi_indirect_handle_t grp_handle) {
    auto count = groups.erase(grp_handle);
    return (count == 0) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

  pi_status_t group_add_member(pi_indirect_handle_t grp_handle,
                               pi_indirect_handle_t mbr_handle) {
    auto it = groups.find(grp_handle);
    if (it == groups.end()) return PI_STATUS_TARGET_ERROR;
    auto p = it->second.insert(mbr_handle);
    return (!p.second) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

  pi_status_t group_remove_member(pi_indirect_handle_t grp_handle,
                                  pi_indirect_handle_t mbr_handle) {
    auto it = groups.find(grp_handle);
    if (it == groups.end()) return PI_STATUS_TARGET_ERROR;
    auto count = it->second.erase(mbr_handle);
    return (count == 0) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

  pi_status_t group_set_members(pi_indirect_handle_t grp_handle,
                                size_t num_mbrs,
                                const pi_indirect_handle_t *mbr_handles) {
    auto it = groups.find(grp_handle);
    if (it == groups.end()) return PI_STATUS_TARGET_ERROR;
    it->second.clear();
    it->second.insert(mbr_handles, mbr_handles + num_mbrs);
    return PI_STATUS_SUCCESS;
  }

  pi_status_t entries_fetch(pi_act_prof_fetch_res_t *res) {
    res->num_members = members.size();
    res->num_groups = groups.size();
    constexpr size_t kBufSize = 16384;  // should be large enough for testing
    // members
    {
      char *buf = new char[kBufSize];
      char *buf_ptr = buf;
      for (const auto &p : members) {
        buf_ptr += emit_indirect_handle(buf_ptr, p.first);
        buf_ptr += p.second.emit(buf_ptr);
      }
      res->entries_members = buf;
      res->entries_members_size = std::distance(buf, buf_ptr);
    }
    // groups
    {
      char *buf = new char[kBufSize];
      char *buf_ptr = buf;
      res->mbr_handles = new pi_indirect_handle_t[kBufSize];
      res->num_cumulated_mbr_handles = 0;
      size_t offset = 0;
      for (const auto &p : groups) {
        buf_ptr += emit_indirect_handle(buf_ptr, p.first);
        auto &mbrs = p.second;
        buf_ptr += emit_uint32(buf_ptr, mbrs.size());
        buf_ptr += emit_uint32(buf_ptr, res->num_cumulated_mbr_handles);
        res->num_cumulated_mbr_handles += mbrs.size();
        for (const auto &m : mbrs) res->mbr_handles[offset++] = m;
      }
      res->entries_groups = buf;
      res->entries_groups_size = std::distance(buf, buf_ptr);
    }
    return PI_STATUS_SUCCESS;
  }

 private:
  using GroupMembers = std::unordered_set<pi_indirect_handle_t>;
  std::unordered_map<pi_indirect_handle_t, ActionData> members{};
  std::unordered_map<pi_indirect_handle_t, GroupMembers> groups{};
  size_t member_counter{0};
  size_t group_counter{1 << 24};
};

class DummyPRE {
 public:
  pi_status_t mc_grp_create(pi_mc_grp_id_t grp_id,
                            pi_mc_grp_handle_t *grp_handle) {
    pi_mc_grp_handle_t grp_h = static_cast<pi_mc_grp_handle_t>(grp_id);
    auto p = mc_grps.insert(grp_h);
    if (!p.second) return PI_STATUS_TARGET_ERROR;
    *grp_handle = grp_h;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t mc_grp_delete(pi_mc_grp_handle_t grp_handle) {
    auto c = mc_grps.erase(grp_handle);
    return (c == 0) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

  pi_status_t mc_node_create(pi_mc_rid_t rid,
                             size_t eg_ports_count,
                             const pi_mc_port_t *eg_ports,
                             pi_mc_node_handle_t *node_handle) {
    mc_nodes.emplace(node_counter,
                     McNode(node_counter, rid, eg_ports_count, eg_ports));
    *node_handle = node_counter++;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t mc_node_modify(pi_mc_node_handle_t node_handle,
                             size_t eg_ports_count,
                             const pi_mc_port_t *eg_ports) {
    auto it = mc_nodes.find(node_handle);
    if (it == mc_nodes.end()) return PI_STATUS_TARGET_ERROR;
    it->second.set_ports(eg_ports_count, eg_ports);
    return PI_STATUS_SUCCESS;
  }

  pi_status_t mc_node_delete(pi_mc_node_handle_t node_handle) {
    auto c = mc_nodes.erase(node_handle);
    return (c == 0) ? PI_STATUS_TARGET_ERROR : PI_STATUS_SUCCESS;
  }

  pi_status_t mc_grp_attach_node(pi_mc_grp_handle_t grp_handle,
                                 pi_mc_node_handle_t node_handle) {
    auto it = mc_nodes.find(node_handle);
    if (it == mc_nodes.end()) return PI_STATUS_TARGET_ERROR;
    if (it->second.attached_to.is_initialized()) return PI_STATUS_TARGET_ERROR;
    it->second.attached_to = grp_handle;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t mc_grp_detach_node(pi_mc_grp_handle_t grp_handle,
                                 pi_mc_node_handle_t node_handle) {
    (void)grp_handle;
    auto it = mc_nodes.find(node_handle);
    if (it == mc_nodes.end()) return PI_STATUS_TARGET_ERROR;
    if (!it->second.attached_to.is_initialized()) return PI_STATUS_TARGET_ERROR;
    it->second.attached_to = boost::none;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t clone_session_set(
      pi_clone_session_id_t clone_session_id,
      const pi_clone_session_config_t *clone_session_config) {
    (void)clone_session_id;
    (void)clone_session_config;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t clone_session_reset(pi_clone_session_id_t clone_session_id) {
    (void)clone_session_id;
    return PI_STATUS_SUCCESS;
  }

 private:
  struct McNode {
    pi_mc_node_handle_t node_handle;
    pi_mc_rid_t rid;
    std::vector<pi_mc_port_t> eg_ports;
    boost::optional<pi_mc_grp_handle_t> attached_to;

    McNode(pi_mc_node_handle_t node_handle,
           pi_mc_rid_t rid,
           size_t eg_ports_count,
           const pi_mc_port_t *eg_ports)
        : node_handle(node_handle), rid(rid) {
      set_ports(eg_ports_count, eg_ports);
    }

    void set_ports(size_t eg_ports_count, const pi_mc_port_t *eg_ports) {
      if (eg_ports_count == 0)
        this->eg_ports.clear();
      else
        this->eg_ports.assign(eg_ports, eg_ports + eg_ports_count);
    }
  };

  std::unordered_map<pi_mc_node_handle_t, McNode> mc_nodes;
  std::unordered_set<pi_mc_grp_handle_t> mc_grps;
  size_t node_counter{0};
};

}  // namespace

class DummySwitch {
 public:
  explicit DummySwitch(device_id_t device_id)
      : device_id(device_id) { }

  pi_status_t table_entry_add(pi_p4_id_t table_id,
                              const pi_match_key_t *match_key,
                              const pi_table_entry_t *table_entry,
                              pi_entry_handle_t *entry_handle) {
    return get_table(table_id).entry_add(match_key, table_entry, entry_handle);
  }

  pi_status_t table_default_action_set(pi_p4_id_t table_id,
                                       const pi_table_entry_t *table_entry) {
    return get_table(table_id).default_action_set(table_entry);
  }

  pi_status_t table_default_action_reset(pi_p4_id_t table_id) {
    return get_table(table_id).default_action_reset();
  }

  pi_status_t table_default_action_get(pi_p4_id_t table_id,
                                       pi_table_entry_t *table_entry) {
    return get_table(table_id).default_action_get(table_entry);
  }

  pi_status_t table_entry_delete_wkey(pi_p4_id_t table_id,
                                      const pi_match_key_t *match_key) {
    return get_table(table_id).entry_delete_wkey(match_key);
  }

  pi_status_t table_entry_modify_wkey(pi_p4_id_t table_id,
                                      const pi_match_key_t *match_key,
                                      const pi_table_entry_t *table_entry) {
    return get_table(table_id).entry_modify_wkey(match_key, table_entry);
  }

  pi_status_t table_entries_fetch(pi_p4_id_t table_id,
                                  pi_table_fetch_res_t *res) {
    return get_table(table_id).entries_fetch(res);
  }

  pi_status_t table_idle_timeout_config_set(
      pi_p4_id_t table_id, const pi_idle_timeout_config_t *config) {
    return get_table(table_id).idle_timeout_config_set(config);
  }

  pi_status_t table_entry_get_remaining_ttl(pi_p4_id_t table_id,
                                            pi_entry_handle_t entry_handle,
                                            uint64_t *ttl_ns) {
    return get_table(table_id).entry_get_remaining_ttl(entry_handle, ttl_ns);
  }

  pi_status_t action_prof_member_create(pi_p4_id_t act_prof_id,
                                        const pi_action_data_t *action_data,
                                        pi_indirect_handle_t *mbr_handle) {
    // constructs DummyActionProf if not already in map
    return action_profs[act_prof_id].member_create(action_data, mbr_handle);
  }

  pi_status_t action_prof_member_modify(pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t mbr_handle,
                                        const pi_action_data_t *action_data) {
    return action_profs[act_prof_id].member_modify(mbr_handle, action_data);
  }

  pi_status_t action_prof_member_delete(pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t mbr_handle) {
    return action_profs[act_prof_id].member_delete(mbr_handle);
  }

  pi_status_t action_prof_group_create(pi_p4_id_t act_prof_id,
                                       size_t max_size,
                                       pi_indirect_handle_t *grp_handle) {
    return action_profs[act_prof_id].group_create(max_size, grp_handle);
  }

  pi_status_t action_prof_group_delete(pi_p4_id_t act_prof_id,
                                       pi_indirect_handle_t grp_handle) {
    return action_profs[act_prof_id].group_delete(grp_handle);
  }

  pi_status_t action_prof_group_add_member(pi_p4_id_t act_prof_id,
                                           pi_indirect_handle_t grp_handle,
                                           pi_indirect_handle_t mbr_handle) {
    return action_profs[act_prof_id].group_add_member(grp_handle, mbr_handle);
  }

  pi_status_t action_prof_group_remove_member(pi_p4_id_t act_prof_id,
                                              pi_indirect_handle_t grp_handle,
                                              pi_indirect_handle_t mbr_handle) {
    return action_profs[act_prof_id].group_remove_member(
        grp_handle, mbr_handle);
  }

  pi_status_t action_prof_group_set_members(
      pi_p4_id_t act_prof_id,
      pi_indirect_handle_t grp_handle,
      size_t num_mbrs,
      const pi_indirect_handle_t *mbr_handles) {
    return action_profs[act_prof_id].group_set_members(
        grp_handle, num_mbrs, mbr_handles);
  }

  pi_status_t action_prof_entries_fetch(pi_p4_id_t act_prof_id,
                                        pi_act_prof_fetch_res_t *res) {
    return action_profs[act_prof_id].entries_fetch(res);
  }

  pi_status_t meter_read(pi_p4_id_t meter_id, size_t index,
                         pi_meter_spec_t *meter_spec) {
    return meters[meter_id].read(index, meter_spec);
  }

  pi_status_t meter_set(pi_p4_id_t meter_id, size_t index,
                        const pi_meter_spec_t *meter_spec) {
    return meters[meter_id].write(index, meter_spec);
  }

  pi_status_t meter_read_direct(pi_p4_id_t meter_id,
                                pi_entry_handle_t entry_handle,
                                pi_meter_spec_t *meter_spec) {
    return meters[meter_id].read(entry_handle, meter_spec);
  }

  pi_status_t meter_set_direct(pi_p4_id_t meter_id,
                               pi_entry_handle_t entry_handle,
                               const pi_meter_spec_t *meter_spec) {
    return meters[meter_id].write(entry_handle, meter_spec);
  }

  pi_status_t counter_read(pi_p4_id_t counter_id, size_t index, int flags,
                           pi_counter_data_t *counter_data) {
    (void) flags;
    return counters[counter_id].read(index, counter_data);
  }

  pi_status_t counter_write(pi_p4_id_t counter_id, size_t index,
                            const pi_counter_data_t *counter_data) {
    return counters[counter_id].write(index, counter_data);
  }

  pi_status_t counter_read_direct(pi_p4_id_t counter_id,
                                  pi_entry_handle_t entry_handle, int flags,
                                  pi_counter_data_t *counter_data) {
    (void) flags;
    return counters[counter_id].read(entry_handle, counter_data);
  }

  pi_status_t counter_write_direct(pi_p4_id_t counter_id,
                                   pi_entry_handle_t entry_handle,
                                   const pi_counter_data_t *counter_data) {
    return counters[counter_id].write(entry_handle, counter_data);
  }

  pi_status_t packetout_send(const char *, size_t) {
    return PI_STATUS_SUCCESS;
  }

  pi_status_t packetin_inject(const std::string &packet) const {
    return pi_packetin_receive(device_id, packet.data(), packet.size());
  }

  pi_status_t mc_grp_create(pi_mc_grp_id_t grp_id,
                            pi_mc_grp_handle_t *grp_handle) {
    return pre.mc_grp_create(grp_id, grp_handle);
  }

  pi_status_t mc_grp_delete(pi_mc_grp_handle_t grp_handle) {
    return pre.mc_grp_delete(grp_handle);
  }

  pi_status_t mc_node_create(pi_mc_rid_t rid,
                             size_t eg_ports_count,
                             const pi_mc_port_t *eg_ports,
                             pi_mc_node_handle_t *node_handle) {
    return pre.mc_node_create(rid, eg_ports_count, eg_ports, node_handle);
  }

  pi_status_t mc_node_modify(pi_mc_node_handle_t node_handle,
                             size_t eg_ports_count,
                             const pi_mc_port_t *eg_ports) {
    return pre.mc_node_modify(node_handle, eg_ports_count, eg_ports);
  }

  pi_status_t mc_node_delete(pi_mc_node_handle_t node_handle) {
    return pre.mc_node_delete(node_handle);
  }

  pi_status_t mc_grp_attach_node(pi_mc_grp_handle_t grp_handle,
                                 pi_mc_node_handle_t node_handle) {
    return pre.mc_grp_attach_node(grp_handle, node_handle);
  }

  pi_status_t mc_grp_detach_node(pi_mc_grp_handle_t grp_handle,
                                 pi_mc_node_handle_t node_handle) {
    return pre.mc_grp_detach_node(grp_handle, node_handle);
  }

  pi_status_t clone_session_set(
      pi_clone_session_id_t clone_session_id,
      const pi_clone_session_config_t *clone_session_config) {
    return pre.clone_session_set(clone_session_id, clone_session_config);
  }

  pi_status_t clone_session_reset(pi_clone_session_id_t clone_session_id) {
    return pre.clone_session_reset(clone_session_id);
  }

  pi_status_t learn_config_set(pi_p4_id_t learn_id,
                               const pi_learn_config_t *config) {
    (void)learn_id;
    (void)config;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t learn_msg_ack(pi_p4_id_t learn_id, pi_learn_msg_id_t msg_id) {
    (void)learn_id;
    (void)msg_id;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t learn_msg_done(pi_learn_msg_t *msg) {
    delete[] msg->entries;
    delete msg;
    return PI_STATUS_SUCCESS;
  }

  pi_status_t learn_new_msg(pi_p4_id_t learn_id,
                            pi_learn_msg_id_t msg_id,
                            const std::vector<std::string> &samples) const {
    if (samples.empty()) return PI_STATUS_SUCCESS;
    auto *msg = new pi_learn_msg_t;
    msg->dev_tgt = {device_id, 0xff};
    msg->learn_id = learn_id;
    msg->msg_id = msg_id;
    msg->num_entries = samples.size();
    msg->entry_size = samples.front().size();
    auto *entries = new char[msg->num_entries * msg->entry_size];
    msg->entries = entries;
    std::for_each(samples.begin(), samples.end(),
                  [&entries](const std::string &s) {
      std::memcpy(entries, s.data(), s.size());
      entries += s.size();
    });
    return pi_learn_new_msg(msg);
  }

  pi_status_t age_entry(pi_p4_id_t table_id,
                        pi_entry_handle_t entry_handle) {
    return get_table(table_id).entry_age(device_id, entry_handle);
  }

  void set_p4info(const pi_p4info_t *p4info) {
    this->p4info = p4info;
  }

  void reset() {
    tables.clear();
    action_profs.clear();
    counters.clear();
    meters.clear();
  }

 private:
  DummyTable &get_table(pi_p4_id_t table_id) {
    auto t_it = tables.find(table_id);
    if (t_it == tables.end()) {
      auto &table = tables.emplace(
          table_id, DummyTable(table_id, p4info)).first->second;
      // add pointers to direct resources to DummyTable
      size_t num_direct_resources;
      auto *res_ids = pi_p4info_table_get_direct_resources(
          p4info, table_id, &num_direct_resources);
      for (size_t i = 0; i < num_direct_resources; i++) {
        if (pi_is_direct_counter_id(res_ids[i]))
          table.add_counter(res_ids[i], &counters[res_ids[i]]);
        else if (pi_is_direct_meter_id(res_ids[i]))
          table.add_meter(res_ids[i], &meters[res_ids[i]]);
        else
          assert(0 && "Unsupported direct resource id");
      }
      return table;
    } else {
      return t_it->second;
    }
  }

  const pi_p4info_t *p4info{nullptr};
  std::unordered_map<pi_p4_id_t, DummyTable> tables{};
  std::unordered_map<pi_p4_id_t, DummyActionProf> action_profs{};
  std::unordered_map<pi_p4_id_t, DummyMeter> meters{};
  std::unordered_map<pi_p4_id_t, DummyCounter> counters{};
  DummyPRE pre{};
  device_id_t device_id;
};

DummySwitchMock::DummySwitchMock(device_id_t device_id)
    : sw(new DummySwitch(device_id)) {
  // delegate calls to real object

  auto sw_ = sw.get();

  // cannot use DoAll to combine 2 actions here (call to real object + handle
  // capture), because the handle needs to be captured after the delegated call,
  // but the delegated call is the one which needs to return the status
  ON_CALL(*this, table_entry_add(_, _, _, _))
      .WillByDefault(Invoke(this, &DummySwitchMock::_table_entry_add));
  ON_CALL(*this, table_default_action_set(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_default_action_set));
  ON_CALL(*this, table_default_action_reset(_))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_default_action_reset));
  ON_CALL(*this, table_default_action_get(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_default_action_get));
  ON_CALL(*this, table_entry_delete_wkey(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_entry_delete_wkey));
  ON_CALL(*this, table_entry_modify_wkey(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_entry_modify_wkey));
  ON_CALL(*this, table_entries_fetch(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_entries_fetch));
  ON_CALL(*this, table_idle_timeout_config_set(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_idle_timeout_config_set));
  ON_CALL(*this, table_entry_get_remaining_ttl(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_entry_get_remaining_ttl));

  // cannot use DoAll to combine 2 actions here (call to real object + handle
  // capture), because the handle needs to be captured after the delegated call,
  // but the delegated call is the one which needs to return the status
  ON_CALL(*this, action_prof_member_create(_, _, _))
      .WillByDefault(
          Invoke(this, &DummySwitchMock::_action_prof_member_create));
  ON_CALL(*this, action_prof_member_modify(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::action_prof_member_modify));
  ON_CALL(*this, action_prof_member_delete(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::action_prof_member_delete));
  // same comment as for action_prof_member_create above
  ON_CALL(*this, action_prof_group_create(_, _, _))
      .WillByDefault(Invoke(this, &DummySwitchMock::_action_prof_group_create));
  ON_CALL(*this, action_prof_group_delete(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::action_prof_group_delete));
  ON_CALL(*this, action_prof_group_add_member(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::action_prof_group_add_member));
  ON_CALL(*this, action_prof_group_remove_member(_, _, _))
      .WillByDefault(
          Invoke(sw_, &DummySwitch::action_prof_group_remove_member));
  ON_CALL(*this, action_prof_group_set_members(_, _, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::action_prof_group_set_members));
  ON_CALL(*this, action_prof_entries_fetch(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::action_prof_entries_fetch));
  ON_CALL(*this, action_prof_api_support()).WillByDefault(Return(
      static_cast<int>(PiActProfApiSupport_BOTH)));

  ON_CALL(*this, meter_read(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::meter_read));
  ON_CALL(*this, meter_set(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::meter_set));
  ON_CALL(*this, meter_read_direct(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::meter_read_direct));
  ON_CALL(*this, meter_set_direct(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::meter_set_direct));

  ON_CALL(*this, counter_read(_, _, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::counter_read));
  ON_CALL(*this, counter_write(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::counter_write));
  ON_CALL(*this, counter_read_direct(_, _, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::counter_read_direct));
  ON_CALL(*this, counter_write_direct(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::counter_write_direct));

  ON_CALL(*this, packetout_send(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::packetout_send));

  ON_CALL(*this, mc_grp_create(_, _))
      .WillByDefault(Invoke(this, &DummySwitchMock::_mc_grp_create));
  ON_CALL(*this, mc_grp_delete(_))
      .WillByDefault(Invoke(sw_, &DummySwitch::mc_grp_delete));
  ON_CALL(*this, mc_node_create(_, _, _, _))
      .WillByDefault(Invoke(this, &DummySwitchMock::_mc_node_create));
  ON_CALL(*this, mc_node_modify(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::mc_node_modify));
  ON_CALL(*this, mc_node_modify(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::mc_node_modify));
  ON_CALL(*this, mc_node_delete(_))
      .WillByDefault(Invoke(sw_, &DummySwitch::mc_node_delete));
  ON_CALL(*this, mc_grp_attach_node(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::mc_grp_attach_node));
  ON_CALL(*this, mc_grp_detach_node(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::mc_grp_detach_node));

  ON_CALL(*this, clone_session_set(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::clone_session_set));
  ON_CALL(*this, clone_session_reset(_))
      .WillByDefault(Invoke(sw_, &DummySwitch::clone_session_reset));

  ON_CALL(*this, learn_config_set(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::learn_config_set));
  ON_CALL(*this, learn_msg_ack(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::learn_msg_ack));
  ON_CALL(*this, learn_msg_done(_))
      .WillByDefault(Invoke(sw_, &DummySwitch::learn_msg_done));
}

DummySwitchMock::~DummySwitchMock() = default;

pi_status_t
DummySwitchMock::_table_entry_add(pi_p4_id_t table_id,
                                  const pi_match_key_t *match_key,
                                  const pi_table_entry_t *table_entry,
                                  pi_entry_handle_t *h) {
  auto r = sw->table_entry_add(table_id, match_key, table_entry, h);
  if (r == PI_STATUS_SUCCESS) table_h = *h;
  return r;
}

pi_entry_handle_t
DummySwitchMock::get_table_entry_handle() const {
  return table_h;
}

pi_status_t
DummySwitchMock::_action_prof_member_create(pi_p4_id_t act_prof_id,
                                            const pi_action_data_t *action_data,
                                            pi_indirect_handle_t *h) {
  auto r = sw->action_prof_member_create(act_prof_id, action_data, h);
  if (r == PI_STATUS_SUCCESS) action_prof_h = *h;
  return r;
}

pi_status_t
DummySwitchMock::_action_prof_group_create(pi_p4_id_t act_prof_id,
                                           size_t max_size,
                                           pi_indirect_handle_t *h) {
  auto r = sw->action_prof_group_create(act_prof_id, max_size, h);
  if (r == PI_STATUS_SUCCESS) action_prof_h = *h;
  return r;
}

pi_indirect_handle_t
DummySwitchMock::get_action_prof_handle() const {
  return action_prof_h;
}

pi_status_t
DummySwitchMock::_mc_grp_create(pi_mc_grp_id_t grp_id,
                                pi_mc_grp_handle_t *grp_handle) {
  auto r = sw->mc_grp_create(grp_id, grp_handle);
  if (r == PI_STATUS_SUCCESS) mc_grp_h = *grp_handle;
  return r;
}

pi_mc_grp_handle_t
DummySwitchMock::get_mc_grp_handle() const {
  return mc_grp_h;
}

pi_status_t
DummySwitchMock::_mc_node_create(pi_mc_rid_t rid,
                                 size_t eg_ports_count,
                                 const pi_mc_port_t *eg_ports,
                                 pi_mc_node_handle_t *node_handle) {
  auto r = sw->mc_node_create(rid, eg_ports_count, eg_ports, node_handle);
  if (r == PI_STATUS_SUCCESS) mc_node_h = *node_handle;
  return r;
}

pi_mc_node_handle_t
DummySwitchMock::get_mc_node_handle() const {
  return mc_node_h;
}

pi_status_t
DummySwitchMock::packetin_inject(const std::string &packet) const {
  return sw->packetin_inject(packet);
}

pi_status_t
DummySwitchMock::digest_inject(pi_p4_id_t learn_id,
                               pi_learn_msg_id_t msg_id,
                               const std::vector<std::string> &samples) const {
  return sw->learn_new_msg(learn_id, msg_id, samples);
}

pi_status_t
DummySwitchMock::age_entry(pi_p4_id_t table_id,
                           pi_entry_handle_t entry_handle) const {
  return sw->age_entry(table_id, entry_handle);
}

void
DummySwitchMock::set_p4info(const pi_p4info_t *p4info) {
  sw->set_p4info(p4info);
}

void
DummySwitchMock::reset() {
  sw->reset();
}

namespace {

// here we implement the _pi_* methods which are needed for our tests
extern "C" {

pi_status_t _pi_init(void *) { return PI_STATUS_SUCCESS; }

pi_status_t _pi_destroy() { return PI_STATUS_SUCCESS; }

pi_status_t _pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                              pi_assign_extra_t *) {
  auto *sw = DeviceResolver::get_switch(dev_id);
  sw->reset();
  sw->set_p4info(p4info);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_update_device_start(pi_dev_id_t dev_id,
                                    const pi_p4info_t *p4info,
                                    const char *, size_t) {
  auto *sw = DeviceResolver::get_switch(dev_id);
  sw->reset();
  sw->set_p4info(p4info);
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_update_device_end(pi_dev_id_t) { return PI_STATUS_SUCCESS; }

pi_status_t _pi_remove_device(pi_dev_id_t) { return PI_STATUS_SUCCESS; }

pi_status_t _pi_session_init(pi_session_handle_t *) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_session_cleanup(pi_session_handle_t) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_batch_begin(pi_session_handle_t) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_batch_end(pi_session_handle_t, bool) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_add(pi_session_handle_t,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                int overwrite,
                                pi_entry_handle_t *entry_handle) {
  (void)overwrite;
  return DeviceResolver::get_switch(dev_tgt.dev_id)->table_entry_add(
      table_id, match_key, table_entry, entry_handle);
}

pi_status_t _pi_table_default_action_set(pi_session_handle_t,
                                         pi_dev_tgt_t dev_tgt,
                                         pi_p4_id_t table_id,
                                         const pi_table_entry_t *table_entry) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->table_default_action_set(
      table_id, table_entry);
}

pi_status_t _pi_table_default_action_reset(pi_session_handle_t,
                                           pi_dev_tgt_t dev_tgt,
                                           pi_p4_id_t table_id) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->table_default_action_reset(
      table_id);
}

pi_status_t _pi_table_default_action_get(pi_session_handle_t,
                                         pi_dev_id_t dev_id,
                                         pi_p4_id_t table_id,
                                         pi_table_entry_t *table_entry) {
  return DeviceResolver::get_switch(dev_id)->table_default_action_get(
      table_id, table_entry);
}

// TODO(antonin): implement when default_action_get is supported
pi_status_t _pi_table_default_action_done(pi_session_handle_t,
                                          pi_table_entry_t *table_entry) {
  (void) table_entry;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_delete(pi_session_handle_t,
                                   pi_dev_id_t,
                                   pi_p4_id_t,
                                   pi_entry_handle_t) {
  return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_table_entry_delete_wkey(pi_session_handle_t,
                                        pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                        const pi_match_key_t *match_key) {
  return DeviceResolver::get_switch(dev_id)->table_entry_delete_wkey(
      table_id, match_key);
}

pi_status_t _pi_table_entry_modify_wkey(pi_session_handle_t,
                                        pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                        const pi_match_key_t *match_key,
                                        const pi_table_entry_t *table_entry) {
  return DeviceResolver::get_switch(dev_id)->table_entry_modify_wkey(
      table_id, match_key, table_entry);
}

pi_status_t _pi_table_entry_modify(pi_session_handle_t,
                                   pi_dev_id_t, pi_p4_id_t,
                                   pi_entry_handle_t,
                                   const pi_table_entry_t *) {
  return PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_table_entries_fetch(pi_session_handle_t,
                                    pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                    pi_table_fetch_res_t *res) {
  return DeviceResolver::get_switch(dev_id)->table_entries_fetch(
      table_id, res);
}

pi_status_t _pi_table_entries_fetch_done(pi_session_handle_t,
                                         pi_table_fetch_res_t *res) {
  delete[] res->entries;
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_idle_timeout_config_set(
    pi_session_handle_t,
    pi_dev_id_t dev_id,
    pi_p4_id_t table_id,
    const pi_idle_timeout_config_t *config) {
  return DeviceResolver::get_switch(dev_id)->table_idle_timeout_config_set(
      table_id, config);
}

pi_status_t _pi_table_entry_get_remaining_ttl(pi_session_handle_t,
                                              pi_dev_id_t dev_id,
                                              pi_p4_id_t table_id,
                                              pi_entry_handle_t entry_handle,
                                              uint64_t *ttl_ns) {
  return DeviceResolver::get_switch(dev_id)->table_entry_get_remaining_ttl(
      table_id, entry_handle, ttl_ns);
}

pi_status_t _pi_act_prof_mbr_create(pi_session_handle_t,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id,
                                    const pi_action_data_t *action_data,
                                    pi_indirect_handle_t *mbr_handle) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->action_prof_member_create(
      act_prof_id, action_data, mbr_handle);
}

pi_status_t _pi_act_prof_mbr_delete(pi_session_handle_t,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle) {
  return DeviceResolver::get_switch(dev_id)->action_prof_member_delete(
      act_prof_id, mbr_handle);
}

pi_status_t _pi_act_prof_mbr_modify(pi_session_handle_t,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t mbr_handle,
                                    const pi_action_data_t *action_data) {
  return DeviceResolver::get_switch(dev_id)->action_prof_member_modify(
      act_prof_id, mbr_handle, action_data);
}

pi_status_t _pi_act_prof_grp_create(pi_session_handle_t,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_p4_id_t act_prof_id, size_t max_size,
                                    pi_indirect_handle_t *grp_handle) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->action_prof_group_create(
      act_prof_id, max_size, grp_handle);
}

pi_status_t _pi_act_prof_grp_delete(pi_session_handle_t,
                                    pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                    pi_indirect_handle_t grp_handle) {
  return DeviceResolver::get_switch(dev_id)->action_prof_group_delete(
      act_prof_id, grp_handle);
}

pi_status_t _pi_act_prof_grp_add_mbr(pi_session_handle_t,
                                     pi_dev_id_t dev_id, pi_p4_id_t act_prof_id,
                                     pi_indirect_handle_t grp_handle,
                                     pi_indirect_handle_t mbr_handle) {
  return DeviceResolver::get_switch(dev_id)->action_prof_group_add_member(
      act_prof_id, grp_handle, mbr_handle);
}

pi_status_t _pi_act_prof_grp_remove_mbr(pi_session_handle_t,
                                        pi_dev_id_t dev_id,
                                        pi_p4_id_t act_prof_id,
                                        pi_indirect_handle_t grp_handle,
                                        pi_indirect_handle_t mbr_handle) {
  return DeviceResolver::get_switch(dev_id)->action_prof_group_remove_member(
      act_prof_id, grp_handle, mbr_handle);
}

pi_status_t _pi_act_prof_grp_set_mbrs(pi_session_handle_t,
                                      pi_dev_id_t dev_id,
                                      pi_p4_id_t act_prof_id,
                                      pi_indirect_handle_t grp_handle,
                                      size_t num_mbrs,
                                      const pi_indirect_handle_t *mbr_handles) {
  return DeviceResolver::get_switch(dev_id)->action_prof_group_set_members(
      act_prof_id, grp_handle, num_mbrs, mbr_handles);
}

pi_status_t _pi_act_prof_entries_fetch(pi_session_handle_t,
                                       pi_dev_id_t dev_id,
                                       pi_p4_id_t act_prof_id,
                                       pi_act_prof_fetch_res_t *res) {
  return DeviceResolver::get_switch(dev_id)->action_prof_entries_fetch(
      act_prof_id, res);
}

pi_status_t _pi_act_prof_entries_fetch_done(pi_session_handle_t,
                                            pi_act_prof_fetch_res_t *res) {
  delete[] res->entries_members;
  delete[] res->entries_groups;
  delete[] res->mbr_handles;
  return PI_STATUS_SUCCESS;
}

int _pi_act_prof_api_support(pi_dev_id_t dev_id) {
  return DeviceResolver::get_switch(dev_id)->action_prof_api_support();
}

pi_status_t _pi_meter_read(pi_session_handle_t,
                           pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                           size_t index, pi_meter_spec_t *meter_spec) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->meter_read(
      meter_id, index, meter_spec);
}

pi_status_t _pi_meter_set(pi_session_handle_t,
                          pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                          size_t index, const pi_meter_spec_t *meter_spec) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->meter_set(
      meter_id, index, meter_spec);
}

pi_status_t _pi_meter_read_direct(pi_session_handle_t,
                                  pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                  pi_entry_handle_t entry_handle,
                                  pi_meter_spec_t *meter_spec) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->meter_read_direct(
      meter_id, entry_handle, meter_spec);
}

pi_status_t _pi_meter_set_direct(pi_session_handle_t,
                                 pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                                 pi_entry_handle_t entry_handle,
                                 const pi_meter_spec_t *meter_spec) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->meter_set_direct(
      meter_id, entry_handle, meter_spec);
}

pi_status_t _pi_counter_read(pi_session_handle_t,
                             pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                             size_t index, int flags,
                             pi_counter_data_t *counter_data) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->counter_read(
      counter_id, index, flags, counter_data);
}

pi_status_t _pi_counter_write(pi_session_handle_t,
                              pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                              size_t index,
                              const pi_counter_data_t *counter_data) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->counter_write(
      counter_id, index, counter_data);
}

pi_status_t _pi_counter_read_direct(pi_session_handle_t,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                    pi_entry_handle_t entry_handle, int flags,
                                    pi_counter_data_t *counter_data) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->counter_read_direct(
      counter_id, entry_handle, flags, counter_data);
}


pi_status_t _pi_counter_write_direct(pi_session_handle_t,
                                     pi_dev_tgt_t dev_tgt,
                                     pi_p4_id_t counter_id,
                                     pi_entry_handle_t entry_handle,
                                     const pi_counter_data_t *counter_data) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->counter_write_direct(
      counter_id, entry_handle, counter_data);
}

pi_status_t _pi_counter_hw_sync(pi_session_handle_t,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                PICounterHwSyncCb cb, void *cb_cookie) {
  (void) dev_tgt;
  (void) counter_id;
  (void) cb_cookie;
  return (cb == NULL) ? PI_STATUS_SUCCESS : PI_STATUS_NOT_IMPLEMENTED_BY_TARGET;
}

pi_status_t _pi_packetout_send(pi_dev_id_t dev_id, const char *pkt,
                               size_t size) {
  return DeviceResolver::get_switch(dev_id)->packetout_send(pkt, size);
}

pi_status_t _pi_mc_session_init(pi_mc_session_handle_t *) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_session_cleanup(pi_mc_session_handle_t) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_mc_grp_create(pi_mc_session_handle_t,
                              pi_dev_id_t dev_id,
                              pi_mc_grp_id_t grp_id,
                              pi_mc_grp_handle_t *grp_handle) {
  return DeviceResolver::get_switch(dev_id)->mc_grp_create(grp_id, grp_handle);
}

pi_status_t _pi_mc_grp_delete(pi_mc_session_handle_t,
                              pi_dev_id_t dev_id,
                              pi_mc_grp_handle_t grp_handle) {
  return DeviceResolver::get_switch(dev_id)->mc_grp_delete(grp_handle);
}

pi_status_t _pi_mc_node_create(pi_mc_session_handle_t,
                               pi_dev_id_t dev_id,
                               pi_mc_rid_t rid,
                               size_t eg_ports_count,
                               const pi_mc_port_t *eg_ports,
                               pi_mc_node_handle_t *node_handle) {
  return DeviceResolver::get_switch(dev_id)->mc_node_create(
      rid, eg_ports_count, eg_ports, node_handle);
}

pi_status_t _pi_mc_node_modify(pi_mc_session_handle_t,
                               pi_dev_id_t dev_id,
                               pi_mc_node_handle_t node_handle,
                               size_t eg_ports_count,
                               const pi_mc_port_t *eg_ports) {
  return DeviceResolver::get_switch(dev_id)->mc_node_modify(
      node_handle, eg_ports_count, eg_ports);
}

pi_status_t _pi_mc_node_delete(pi_mc_session_handle_t,
                               pi_dev_id_t dev_id,
                               pi_mc_node_handle_t node_handle) {
  return DeviceResolver::get_switch(dev_id)->mc_node_delete(node_handle);
}

pi_status_t _pi_mc_grp_attach_node(pi_mc_session_handle_t,
                                   pi_dev_id_t dev_id,
                                   pi_mc_grp_handle_t grp_handle,
                                   pi_mc_node_handle_t node_handle) {
  return DeviceResolver::get_switch(dev_id)->mc_grp_attach_node(
      grp_handle, node_handle);
}

pi_status_t _pi_mc_grp_detach_node(pi_mc_session_handle_t,
                                   pi_dev_id_t dev_id,
                                   pi_mc_grp_handle_t grp_handle,
                                   pi_mc_node_handle_t node_handle) {
  return DeviceResolver::get_switch(dev_id)->mc_grp_detach_node(
      grp_handle, node_handle);
}

pi_status_t _pi_clone_session_set(
    pi_session_handle_t,
    pi_dev_tgt_t dev_tgt,
    pi_clone_session_id_t clone_session_id,
    const pi_clone_session_config_t *clone_session_config) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->clone_session_set(
      clone_session_id, clone_session_config);
}

pi_status_t _pi_clone_session_reset(pi_session_handle_t,
                                    pi_dev_tgt_t dev_tgt,
                                    pi_clone_session_id_t clone_session_id) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->clone_session_reset(
      clone_session_id);
}

pi_status_t _pi_learn_config_set(pi_session_handle_t,
                                 pi_dev_id_t dev_id, pi_p4_id_t learn_id,
                                 const pi_learn_config_t *config) {
  return DeviceResolver::get_switch(dev_id)->learn_config_set(learn_id, config);
}

pi_status_t _pi_learn_msg_ack(pi_session_handle_t,
                              pi_dev_id_t dev_id,
                              pi_p4_id_t learn_id,
                              pi_learn_msg_id_t msg_id) {
  return DeviceResolver::get_switch(dev_id)->learn_msg_ack(learn_id, msg_id);
}

pi_status_t _pi_learn_msg_done(pi_learn_msg_t *msg) {
  return DeviceResolver::get_switch(msg->dev_tgt.dev_id)->learn_msg_done(msg);
}

}

}  // namespace

}  // namespace testing
}  // namespace proto
}  // namespace pi
