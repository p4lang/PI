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

#ifndef SRC_TABLE_INFO_STORE_H_
#define SRC_TABLE_INFO_STORE_H_

#include <PI/frontends/cpp/tables.h>
#include <PI/pi.h>

#include <memory>
#include <mutex>
#include <unordered_map>

namespace pi {

namespace fe {

namespace proto {

class TableInfoStoreOne;

class TableInfoStore {
 public:
  // instead of storing proto data (RepeatedPtrField<p4::MatchKey>), we store
  // the PI match key representation. Using protobuf data as a key can become
  // somewhat nighmarish; in particular the order of match fields in the match
  // key should be able to change without impacting the hash or equality
  // operator.
  using MatchKey = pi::MatchKey;

  // wish I could use boost::variant for these
  struct Data {
    Data(pi_entry_handle_t handle, uint64_t controller_metadata)
        : handle(handle), controller_metadata(controller_metadata) { }

    const pi_entry_handle_t handle{0};
    uint64_t controller_metadata{0};
  };

  using Mutex = std::mutex;
  using Lock = std::unique_lock<Mutex>;

  TableInfoStore();

  ~TableInfoStore();

  // Let the client (DeviceMgr) be responsible for locking the table
  // state. This is the only way to guarantee that updates to the state are
  // consistent with lower level driver operations.
  Lock lock_table(pi_p4_id_t t_id) const;

  void add_table(pi_p4_id_t t_id);

  void add_entry(pi_p4_id_t t_id, const MatchKey &mk, const Data &data);

  void remove_entry(pi_p4_id_t t_id, const MatchKey &mk);

  Data *get_entry(pi_p4_id_t t_id, const MatchKey &mk) const;

  void reset();

 private:
  // TableInfoStoreOne includes a mutex, so we need a pointer
  std::unordered_map<pi_p4_id_t, std::unique_ptr<TableInfoStoreOne> > tables;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_TABLE_INFO_STORE_H_
