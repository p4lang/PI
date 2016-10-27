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

#include <arpa/inet.h>

#include <PI/frontends/cpp/tables.h>
#include <PI/p4info.h>

#include <PI/int/pi_int.h>
#include <PI/int/serialize.h>

#include <cstring>

namespace pi {

namespace {

template <typename T>
T endianness(T v);

template <>
uint8_t endianness(uint8_t v) {
  return v;
}

template <>
uint16_t endianness(uint16_t v) {
  return htons(v);
}

template <>
uint32_t endianness(uint32_t v) {
  return htonl(v);
}

// TODO(antonin): portability
uint64_t htonll(uint64_t n) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return n;
#else
  return (((uint64_t)htonl(n)) << 32) + htonl(n >> 32);
#endif
}

template <>
uint64_t endianness(uint64_t v) {
  return htonll(v);
}

}  // namespace

MatchKey::MatchKey(const pi_p4info_t *p4info, pi_p4_id_t table_id)
    : p4info(p4info), table_id(table_id) {
  size_t s = 0;
  size_t num_match_fields = pi_p4info_table_num_match_fields(p4info, table_id);
  offsets.resize(num_match_fields);
  for (size_t i = 0; i < num_match_fields; i++) {
    offsets[i] = s;
    pi_p4info_match_field_info_t finfo;
    pi_p4info_table_match_field_info(p4info, table_id, i, &finfo);
    size_t nbytes = (finfo.bitwidth + 7) / 8;
    switch (finfo.match_type) {
      case PI_P4INFO_MATCH_TYPE_VALID:
        assert(nbytes == 1);
      case PI_P4INFO_MATCH_TYPE_EXACT:
        s += nbytes;
        break;
      case PI_P4INFO_MATCH_TYPE_LPM:
        s += nbytes + sizeof(uint32_t);
        break;
      case PI_P4INFO_MATCH_TYPE_TERNARY:
      case PI_P4INFO_MATCH_TYPE_RANGE:
        s += 2 * nbytes;
        break;
      default:
        assert(0);
    }
  }

  // std::allocator is using standard new, no alignment issue
  _data.resize(sizeof(*match_key) + s);
  match_key = reinterpret_cast<decltype(match_key)>(_data.data());
  match_key->p4info = p4info;
  match_key->table_id = table_id;
  match_key->priority = 0;
  match_key->data_size = s;
  match_key->data = _data.data() + sizeof(*match_key);
}

MatchKey::~MatchKey() { }

void
MatchKey::reset() {
  nset = 0;
  match_key->priority = 0;
}

void
MatchKey::set_priority(int priority) {
  match_key->priority = priority;
}

template <typename T>
error_code_t
MatchKey::format(pi_p4_id_t f_id, T v, size_t offset, size_t *written) {
  constexpr size_t type_bitwidth = sizeof(T) * 8;
  const size_t bitwidth = pi_p4info_field_bitwidth(p4info, f_id);
  const size_t bytes = (bitwidth + 7) / 8;
  const char byte0_mask = pi_p4info_field_byte0_mask(p4info, f_id);
  if (bitwidth > type_bitwidth) return 1;
  v = endianness(v);
  char *data = reinterpret_cast<char *>(&v);
  data += sizeof(T) - bytes;
  data[0] &= byte0_mask;
  memcpy(match_key->data + offset, data, bytes);
  *written = bytes;
  return 0;
}

error_code_t
MatchKey::format(pi_p4_id_t f_id, const char *ptr, size_t s, size_t offset,
                 size_t *written) {
  // constexpr size_t type_bitwidth = sizeof(T) * 8;
  const size_t bitwidth = pi_p4info_field_bitwidth(p4info, f_id);
  const size_t bytes = (bitwidth + 7) / 8;
  const char byte0_mask = pi_p4info_field_byte0_mask(p4info, f_id);
  if (bytes != s) return 1;
  char *dst = match_key->data + offset;
  memcpy(dst, ptr, bytes);
  dst[0] &= byte0_mask;
  *written = bytes;
  return 0;
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
MatchKey::set_exact(pi_p4_id_t f_id, T key) {
  // explicit instantiation below so compile time check not possible
  assert((!std::is_signed<T>::value) && "signed fields not supported yet");
  size_t f_index = pi_p4info_table_match_field_index(p4info, table_id, f_id);
  size_t offset = offsets.at(f_index);
  size_t written = 0;
  return format(f_id, key, offset, &written);
}

template error_code_t MatchKey::set_exact<uint8_t>(pi_p4_id_t, uint8_t);
template error_code_t MatchKey::set_exact<uint16_t>(pi_p4_id_t, uint16_t);
template error_code_t MatchKey::set_exact<uint32_t>(pi_p4_id_t, uint32_t);
template error_code_t MatchKey::set_exact<uint64_t>(pi_p4_id_t, uint64_t);
template error_code_t MatchKey::set_exact<int8_t>(pi_p4_id_t, int8_t);
template error_code_t MatchKey::set_exact<int16_t>(pi_p4_id_t, int16_t);
template error_code_t MatchKey::set_exact<int32_t>(pi_p4_id_t, int32_t);
template error_code_t MatchKey::set_exact<int64_t>(pi_p4_id_t, int64_t);

error_code_t
MatchKey::set_exact(pi_p4_id_t f_id, const char *key, size_t s) {
  size_t f_index = pi_p4info_table_match_field_index(p4info, table_id, f_id);
  size_t offset = offsets.at(f_index);
  size_t written = 0;
  return format(f_id, key, s, offset, &written);
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
MatchKey::set_lpm(pi_p4_id_t f_id, T key, int prefix_length) {
  // explicit instantiation below so compile time check not possible
  assert((!std::is_signed<T>::value) && "signed fields not supported yet");
  size_t f_index = pi_p4info_table_match_field_index(p4info, table_id, f_id);
  size_t offset = offsets.at(f_index);
  size_t written = 0;
  error_code_t rc;
  rc = format(f_id, key, offset, &written);
  offset += written;
  emit_uint32(match_key->data + offset, prefix_length);
  return rc;
}

template error_code_t MatchKey::set_lpm<uint8_t>(pi_p4_id_t, uint8_t, int);
template error_code_t MatchKey::set_lpm<uint16_t>(pi_p4_id_t, uint16_t, int);
template error_code_t MatchKey::set_lpm<uint32_t>(pi_p4_id_t, uint32_t, int);
template error_code_t MatchKey::set_lpm<uint64_t>(pi_p4_id_t, uint64_t, int);
template error_code_t MatchKey::set_lpm<int8_t>(pi_p4_id_t, int8_t, int);
template error_code_t MatchKey::set_lpm<int16_t>(pi_p4_id_t, int16_t, int);
template error_code_t MatchKey::set_lpm<int32_t>(pi_p4_id_t, int32_t, int);
template error_code_t MatchKey::set_lpm<int64_t>(pi_p4_id_t, int64_t, int);

error_code_t
MatchKey::set_lpm(pi_p4_id_t f_id, const char *key, size_t s,
                  int prefix_length) {
  size_t f_index = pi_p4info_table_match_field_index(p4info, table_id, f_id);
  size_t offset = offsets.at(f_index);
  size_t written = 0;
  error_code_t rc;
  rc = format(f_id, key, s, offset, &written);
  offset += written;
  emit_uint32(match_key->data + offset, prefix_length);
  return rc;
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
MatchKey::set_ternary(pi_p4_id_t f_id, T key, T mask) {
  // explicit instantiation below so compile time check not possible
  assert((!std::is_signed<T>::value) && "signed fields not supported yet");
  size_t f_index = pi_p4info_table_match_field_index(p4info, table_id, f_id);
  size_t offset = offsets.at(f_index);
  size_t written = 0;
  error_code_t rc;
  rc = format(f_id, key, offset, &written);
  offset += written;
  if (rc) return rc;
  rc = format(f_id, mask, offset, &written);
  return rc;
}

template error_code_t MatchKey::set_ternary<uint8_t>(pi_p4_id_t, uint8_t,
                                                     uint8_t);
template error_code_t MatchKey::set_ternary<uint16_t>(pi_p4_id_t, uint16_t,
                                                      uint16_t);
template error_code_t MatchKey::set_ternary<uint32_t>(pi_p4_id_t, uint32_t,
                                                      uint32_t);
template error_code_t MatchKey::set_ternary<uint64_t>(pi_p4_id_t, uint64_t,
                                                      uint64_t);
template error_code_t MatchKey::set_ternary<int8_t>(pi_p4_id_t, int8_t,
                                                    int8_t);
template error_code_t MatchKey::set_ternary<int16_t>(pi_p4_id_t, int16_t,
                                                     int16_t);
template error_code_t MatchKey::set_ternary<int32_t>(pi_p4_id_t, int32_t,
                                                     int32_t);
template error_code_t MatchKey::set_ternary<int64_t>(pi_p4_id_t, int64_t,
                                                     int64_t);

error_code_t
MatchKey::set_ternary(pi_p4_id_t f_id, const char *key, const char *mask,
                      size_t s) {
  size_t f_index = pi_p4info_table_match_field_index(p4info, table_id, f_id);
  size_t offset = offsets.at(f_index);
  size_t written = 0;
  error_code_t rc;
  rc = format(f_id, key, s, offset, &written);
  if (rc) return rc;
  offset += written;
  rc = format(f_id, mask, s, offset, &written);
  return rc;
}

ActionData::ActionData(const pi_p4info_t *p4info, pi_p4_id_t action_id)
    : p4info(p4info), action_id(action_id) {
  size_t s = 0;
  size_t num_params;
  const pi_p4_id_t *params = pi_p4info_action_get_params(p4info, action_id,
                                                         &num_params);
  offsets.resize(num_params);
  for (size_t i = 0; i < num_params; i++) {
    size_t bitwidth = pi_p4info_action_param_bitwidth(p4info, params[i]);
    offsets[i] = s;
    s += (bitwidth + 7) / 8;
  }

  // using standard new, no alignment issue
  _data.resize(sizeof(*action_data) + s);
  action_data = reinterpret_cast<decltype(action_data)>(_data.data());
  action_data->p4info = p4info;
  action_data->action_id = action_id;
  action_data->data_size = s;
  action_data->data = _data.data() + sizeof(*action_data);
}

ActionData::~ActionData() { }

void
ActionData::reset() {
  nset = 0;
}

template <typename T>
error_code_t
ActionData::format(pi_p4_id_t ap_id, T v, size_t offset) {
  constexpr size_t type_bitwidth = sizeof(T) * 8;
  const size_t bitwidth = pi_p4info_action_param_bitwidth(p4info, ap_id);
  const size_t bytes = (bitwidth + 7) / 8;
  const char byte0_mask = pi_p4info_action_param_byte0_mask(p4info, ap_id);
  if (bitwidth > type_bitwidth) return 1;
  v = endianness(v);
  char *data = reinterpret_cast<char *>(&v);
  data += sizeof(T) - bytes;
  data[0] &= byte0_mask;
  memcpy(action_data->data + offset, data, bytes);
  return 0;
}

error_code_t
ActionData::format(pi_p4_id_t ap_id, const char *ptr, size_t s, size_t offset) {
  // constexpr size_t type_bitwidth = sizeof(T) * 8;
  const size_t bitwidth = pi_p4info_action_param_bitwidth(p4info, ap_id);
  const size_t bytes = (bitwidth + 7) / 8;
  const char byte0_mask = pi_p4info_action_param_byte0_mask(p4info, ap_id);
  if (bytes != s) return 1;
  char *dst = action_data->data + offset;
  memcpy(dst, ptr, bytes);
  dst[0] &= byte0_mask;
  return 0;
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
ActionData::set_arg(pi_p4_id_t ap_id, T arg) {
  // explicit instantiation below so compile time check not possible
  assert((!std::is_signed<T>::value) && "signed params not supported yet");
  size_t index = ap_id & 0xff;
  return format(ap_id, arg, offsets.at(index));
}

error_code_t
ActionData::set_arg(pi_p4_id_t ap_id, const char *arg, size_t s) {
  size_t index = ap_id & 0xff;
  return format(ap_id, arg, s, offsets.at(index));
}

template error_code_t ActionData::set_arg<uint8_t>(pi_p4_id_t, uint8_t);
template error_code_t ActionData::set_arg<uint16_t>(pi_p4_id_t, uint16_t);
template error_code_t ActionData::set_arg<uint32_t>(pi_p4_id_t, uint32_t);
template error_code_t ActionData::set_arg<uint64_t>(pi_p4_id_t, uint64_t);
template error_code_t ActionData::set_arg<int8_t>(pi_p4_id_t, int8_t);
template error_code_t ActionData::set_arg<int16_t>(pi_p4_id_t, int16_t);
template error_code_t ActionData::set_arg<int32_t>(pi_p4_id_t, int32_t);
template error_code_t ActionData::set_arg<int64_t>(pi_p4_id_t, int64_t);


MatchTable::MatchTable(pi_session_handle_t sess, pi_dev_tgt_t dev_tgt,
                       const pi_p4info_t *p4info, pi_p4_id_t table_id)
    : sess(sess), dev_tgt(dev_tgt), p4info(p4info), table_id(table_id) { }

pi_table_entry_t
MatchTable::build_table_entry(const ActionEntry &action_entry) const {
  pi_table_entry_t entry;
  entry.entry_properties = NULL;
  entry.direct_res_config = NULL;

  switch (action_entry.type()) {
    case ActionEntry::Tag::NONE:
      assert(0);
      break;
    case ActionEntry::Tag::ACTION_DATA:
      entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
      entry.entry.action_data = action_entry.action_data().get();
      break;
    case ActionEntry::Tag::INDIRECT_HANDLE:
      entry.entry_type = PI_ACTION_ENTRY_TYPE_INDIRECT;
      entry.entry.indirect_handle = action_entry.indirect_handle();
      break;
  }

  return entry;
}

pi_status_t
MatchTable::entry_add(const MatchKey &match_key,
                      const ActionEntry &action_entry, bool overwrite,
                      pi_entry_handle_t *entry_handle) {
  auto entry = build_table_entry(action_entry);
  return pi_table_entry_add(sess, dev_tgt, table_id, match_key.get(),
                            &entry, overwrite, entry_handle);
}

pi_status_t
MatchTable::entry_add(const MatchKey &match_key,
                      const ActionData &action_data, bool overwrite,
                      pi_entry_handle_t *entry_handle) {
  pi_table_entry_t entry;
  entry.entry_properties = NULL;
  entry.direct_res_config = NULL;
  entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  entry.entry.action_data = action_data.get();
  return pi_table_entry_add(sess, dev_tgt, table_id, match_key.get(),
                            &entry, overwrite, entry_handle);
}

pi_status_t
MatchTable::entry_delete(pi_entry_handle_t entry_handle) {
  return pi_table_entry_delete(sess, dev_tgt.dev_id, table_id, entry_handle);
}

pi_status_t
MatchTable::entry_delete_wkey(const MatchKey &match_key) {
  return pi_table_entry_delete_wkey(sess, dev_tgt.dev_id, table_id,
                                    match_key.get());
}

pi_status_t
MatchTable::default_entry_set(const ActionEntry &action_entry) {
  auto entry = build_table_entry(action_entry);
  return pi_table_default_action_set(sess, dev_tgt, table_id, &entry);
}

pi_status_t
MatchTable::default_entry_set(const ActionData &action_data) {
  pi_table_entry_t entry;
  entry.entry_type = PI_ACTION_ENTRY_TYPE_DATA;
  entry.entry.action_data = action_data.get();
  entry.entry_properties = NULL;
  entry.direct_res_config = NULL;
  return pi_table_default_action_set(sess, dev_tgt, table_id, &entry);
}

}  // namespace pi
