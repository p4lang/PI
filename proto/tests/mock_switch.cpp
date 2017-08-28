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

#include <algorithm>  // std::copy
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "PI/frontends/proto/device_mgr.h"
#include "PI/int/pi_int.h"
#include "PI/int/serialize.h"
#include "PI/pi.h"
#include "PI/target/pi_imp.h"

namespace pi {
namespace proto {
namespace testing {

namespace {

using ::testing::_;
using ::testing::Invoke;

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

  size_t nbytes() const {
    return mk.size();
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

// TODO(antonin): support resources...
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
    return s;
  }

 private:
  pi_action_entry_type_t type;
  // not bothering with a union here
  ActionData ad;
  pi_indirect_handle_t indirect_h;
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

  pi_status_t entry_add(const pi_match_key_t *match_key,
                        const pi_table_entry_t *table_entry,
                        pi_entry_handle_t *entry_handle) {
    auto r = key_to_handle.emplace(DummyMatchKey(match_key), entry_counter);
    // TODO(antonin): we need a better error code for duplicate entry
    if (!r.second) return PI_STATUS_TARGET_ERROR;
    entries.emplace(
        entry_counter,
        Entry(DummyMatchKey(match_key), DummyTableEntry(table_entry)));
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
      buf_ptr += emit_uint32(buf_ptr, 0);  // direct resources
    }
    res->entries = buf;
    res->entries_size = std::distance(buf, buf_ptr);
    return PI_STATUS_SUCCESS;
  }

 private:
  std::unordered_map<pi_entry_handle_t, Entry> entries{};
  std::unordered_map<DummyMatchKey, pi_entry_handle_t, DummyMatchKeyHash>
  key_to_handle{};
  boost::optional<DummyTableEntry> default_entry;
  size_t entry_counter{0};
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

class DummyMeter {
 public:
  // TODO(antonin): store meter_spec for read API
  template <typename T>
  pi_status_t set(T index, const pi_meter_spec_t *meter_spec) {
    (void) index;
    (void) meter_spec;
    return PI_STATUS_SUCCESS;
  }
};

class DummyCounter {
 public:
  // TODO(antonin): write API
  template <typename T>
  pi_status_t read(T index, pi_counter_data_t *counter_data) {
    (void) index;
    counter_data->valid = PI_COUNTER_UNIT_PACKETS | PI_COUNTER_UNIT_BYTES;
    counter_data->bytes = 0;
    counter_data->packets = 0;
    return PI_STATUS_SUCCESS;
  }
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
    // constructs DummyTable if not already in map
    return tables[table_id].entry_add(match_key, table_entry, entry_handle);
  }

  pi_status_t table_default_action_set(pi_p4_id_t table_id,
                                       const pi_table_entry_t *table_entry) {
    return tables[table_id].default_action_set(table_entry);
  }

  pi_status_t table_default_action_get(pi_p4_id_t table_id,
                                       pi_table_entry_t *table_entry) {
    return tables[table_id].default_action_get(table_entry);
  }

  pi_status_t table_entry_delete_wkey(pi_p4_id_t table_id,
                                      const pi_match_key_t *match_key) {
    return tables[table_id].entry_delete_wkey(match_key);
  }

  pi_status_t table_entry_modify_wkey(pi_p4_id_t table_id,
                                      const pi_match_key_t *match_key,
                                      const pi_table_entry_t *table_entry) {
    return tables[table_id].entry_modify_wkey(match_key, table_entry);
  }

  pi_status_t table_entries_fetch(pi_p4_id_t table_id,
                                  pi_table_fetch_res_t *res) {
    return tables[table_id].entries_fetch(res);
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

  pi_status_t action_prof_entries_fetch(pi_p4_id_t act_prof_id,
                                        pi_act_prof_fetch_res_t *res) {
    return action_profs[act_prof_id].entries_fetch(res);
  }

  pi_status_t meter_set(pi_p4_id_t meter_id, size_t index,
                        const pi_meter_spec_t *meter_spec) {
    return meters[meter_id].set(index, meter_spec);
  }

  pi_status_t meter_set_direct(pi_p4_id_t meter_id,
                               pi_entry_handle_t entry_handle,
                               const pi_meter_spec_t *meter_spec) {
    return meters[meter_id].set(entry_handle, meter_spec);
  }

  pi_status_t counter_read(pi_p4_id_t counter_id, size_t index, int flags,
                           pi_counter_data_t *counter_data) {
    (void) flags;
    return counters[counter_id].read(index, counter_data);
  }

  pi_status_t counter_read_direct(pi_p4_id_t counter_id,
                                  pi_entry_handle_t entry_handle, int flags,
                                  pi_counter_data_t *counter_data) {
    (void) flags;
    return counters[counter_id].read(entry_handle, counter_data);
  }

  pi_status_t packetout_send(const char *, size_t) {
    return PI_STATUS_SUCCESS;
  }

  pi_status_t packetin_inject(const std::string &packet) const {
    return pi_packetin_receive(device_id, packet.data(), packet.size());
  }

 private:
  std::unordered_map<pi_p4_id_t, DummyTable> tables{};
  std::unordered_map<pi_p4_id_t, DummyActionProf> action_profs{};
  std::unordered_map<pi_p4_id_t, DummyMeter> meters{};
  std::unordered_map<pi_p4_id_t, DummyCounter> counters{};
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
  ON_CALL(*this, table_default_action_get(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_default_action_get));
  ON_CALL(*this, table_entry_delete_wkey(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_entry_delete_wkey));
  ON_CALL(*this, table_entry_modify_wkey(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_entry_modify_wkey));
  ON_CALL(*this, table_entries_fetch(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::table_entries_fetch));

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
  ON_CALL(*this, action_prof_entries_fetch(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::action_prof_entries_fetch));

  ON_CALL(*this, meter_set(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::meter_set));
  ON_CALL(*this, meter_set_direct(_, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::meter_set_direct));

  ON_CALL(*this, counter_read(_, _, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::counter_read));
  ON_CALL(*this, counter_read_direct(_, _, _, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::counter_read_direct));

  ON_CALL(*this, packetout_send(_, _))
      .WillByDefault(Invoke(sw_, &DummySwitch::packetout_send));
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
DummySwitchMock::packetin_inject(const std::string &packet) const {
  return sw->packetin_inject(packet);
}

namespace {

// here we implement the _pi_* methods which are needed for our tests
extern "C" {

pi_status_t _pi_init(void *) { return PI_STATUS_SUCCESS; }

pi_status_t _pi_destroy() { return PI_STATUS_SUCCESS; }

pi_status_t _pi_assign_device(pi_dev_id_t, const pi_p4info_t *,
                              pi_assign_extra_t *) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_update_device_start(pi_dev_id_t, const pi_p4info_t *,
                                    const char *, size_t) {
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

pi_status_t _pi_meter_set(pi_session_handle_t,
                          pi_dev_tgt_t dev_tgt, pi_p4_id_t meter_id,
                          size_t index, const pi_meter_spec_t *meter_spec) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->meter_set(
      meter_id, index, meter_spec);
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

pi_status_t _pi_counter_read_direct(pi_session_handle_t,
                                    pi_dev_tgt_t dev_tgt, pi_p4_id_t counter_id,
                                    pi_entry_handle_t entry_handle, int flags,
                                    pi_counter_data_t *counter_data) {
  return DeviceResolver::get_switch(dev_tgt.dev_id)->counter_read_direct(
      counter_id, entry_handle, flags, counter_data);
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

}

}  // namespace

}  // namespace testing
}  // namespace proto
}  // namespace pi
