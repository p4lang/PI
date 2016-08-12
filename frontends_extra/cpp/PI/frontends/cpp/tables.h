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

#ifndef PI_FRONTENDS_CPP_TABLES_H_
#define PI_FRONTENDS_CPP_TABLES_H_

#include <memory>
#include <vector>

#include <cstdint>

#include <PI/pi.h>

namespace pi {

// TODO(antonin): temporary
typedef int error_code_t;

class MatchKey {
  friend class MatchTable;
 public:
  MatchKey(const pi_p4info_t *p4info, pi_p4_id_t table_id);
  ~MatchKey();

  void reset();

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
  set_exact(pi_p4_id_t f_id, T key);
  error_code_t set_exact(pi_p4_id_t f_id, const char *key, size_t s);

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
  set_lpm(pi_p4_id_t f_id, T key, int prefix_length);
  error_code_t
  set_lpm(pi_p4_id_t f_id, const char *key, size_t s, int prefix_length);

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
  set_ternary(pi_p4_id_t f_id, T key, T mask);
  error_code_t
  set_ternary(pi_p4_id_t f_id, const char *key, char *mask, size_t s);

 private:
  template <typename T>
  error_code_t format(pi_p4_id_t f_id, T v, size_t offset, size_t *written);
  error_code_t format(pi_p4_id_t f_id, const char *ptr, size_t s,
                      size_t offset, size_t *written);

  pi_match_key_t *get() const {
    return match_key;
  }

  const pi_p4info_t *p4info;
  pi_p4_id_t table_id;
  size_t nset{0};
  std::vector<size_t> offsets{};
  pi_match_key_t *match_key;
  std::unique_ptr<char []> _data;
};

class ActionData {
  friend class MatchTable;
 public:
  ActionData(const pi_p4info_t *p4info, pi_p4_id_t action_id);
  ~ActionData();

  void reset();

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value, error_code_t>::type
  set_arg(pi_p4_id_t ap_id, T arg);
  error_code_t
  set_arg(pi_p4_id_t ap_id, const char *arg, size_t s);

 private:
  template <typename T>
  error_code_t format(pi_p4_id_t ap_id, T v, size_t offset);
  error_code_t format(pi_p4_id_t ap_id, const char *ptr, size_t s,
                      size_t offset);

  pi_action_data_t *get() const {
    return action_data;
  }

  const pi_p4info_t *p4info;
  pi_p4_id_t action_id;
  size_t nset{0};
  std::vector<size_t> offsets{};
  pi_action_data_t *action_data;
  std::unique_ptr<char []> _data;
};

// TODO(antonin): handle device id / pipleline mask
class MatchTable {
 public:
  MatchTable(pi_session_handle_t sess, const pi_p4info_t *p4info,
             pi_p4_id_t table_id);

  error_code_t entry_add(const MatchKey &match_key, pi_p4_id_t action_id,
                         const ActionData &action_data, bool overwrite,
                         pi_entry_handle_t *entry_handle);

  error_code_t entry_delete(pi_entry_handle_t entry_handle);

  // many more APIs

 private:
  pi_session_handle_t sess;
  const pi_p4info_t *p4info;
  pi_p4_id_t table_id;
};

}  // namespace pi

#endif  // PI_FRONTENDS_CPP_TABLES_H_
