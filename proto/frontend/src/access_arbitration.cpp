/* Copyright 2019-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, noware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include "access_arbitration.h"

#include <mutex>
#include <set>

#include "p4/v1/p4runtime.pb.h"

namespace p4v1 = ::p4::v1;

namespace pi {

namespace fe {

namespace proto {

namespace {

template <typename InputIterator1, typename InputIterator2>
bool do_sets_intersect(InputIterator1 first1, InputIterator1 last1,
                       InputIterator2 first2, InputIterator2 last2) {
  while (first1 != last1 && first2 != last2) {
    if (*first1 < *first2) {
      ++first1;
    } else if (*first2 < *first1) {
      ++first2;
    } else {
      return true;
    }
  }
  return false;
}

}  // namespace

AccessArbitration::Access::Access(AccessArbitration *arbitrator)
    : arbitrator(arbitrator) { }

AccessArbitration::Access::~Access() = default;

AccessArbitration::WriteAccess::WriteAccess(AccessArbitration *arbitrator)
    : AccessArbitration::Access(arbitrator) { }

AccessArbitration::WriteAccess::~WriteAccess() {
  arbitrator->release_write_access(*this);
}

AccessArbitration::ReadAccess::ReadAccess(AccessArbitration *arbitrator)
    : AccessArbitration::Access(arbitrator) { }

AccessArbitration::ReadAccess::~ReadAccess() {
  arbitrator->release_read_access();
}

AccessArbitration::NoWriteAccess::NoWriteAccess(AccessArbitration *arbitrator)
    : AccessArbitration::Access(arbitrator) { }

AccessArbitration::NoWriteAccess::~NoWriteAccess() {
  arbitrator->release_no_write_access(*this);
}

AccessArbitration::WriteAccess
AccessArbitration::write_access(const p4v1::WriteRequest &request) {
  WriteAccess access(this);
  auto &p4_ids = access.p4_ids;

  for (const auto &update : request.updates()) {
    const auto &entity = update.entity();
    switch (entity.entity_case()) {
      case p4v1::Entity::kExternEntry:
        break;
      case p4v1::Entity::kTableEntry:
        p4_ids.insert(entity.table_entry().table_id());
        break;
      case p4v1::Entity::kActionProfileMember:
        p4_ids.insert(entity.action_profile_member().action_profile_id());
        break;
      case p4v1::Entity::kActionProfileGroup:
        p4_ids.insert(entity.action_profile_group().action_profile_id());
        break;
      case p4v1::Entity::kMeterEntry:
        p4_ids.insert(entity.meter_entry().meter_id());
        break;
      case p4v1::Entity::kDirectMeterEntry:
        p4_ids.insert(entity.direct_meter_entry().table_entry().table_id());
        break;
      case p4v1::Entity::kCounterEntry:
        p4_ids.insert(entity.counter_entry().counter_id());
        break;
      case p4v1::Entity::kDirectCounterEntry:
        p4_ids.insert(entity.direct_counter_entry().table_entry().table_id());
        break;
      case p4v1::Entity::kPacketReplicationEngineEntry:
        break;
      case p4v1::Entity::kValueSetEntry:
        p4_ids.insert(entity.value_set_entry().value_set_id());
        break;
      case p4v1::Entity::kRegisterEntry:
        p4_ids.insert(entity.register_entry().register_id());
        break;
      case p4v1::Entity::kDigestEntry:
        break;
      default:
        break;
    }
  }

  std::unique_lock<std::mutex> lock(mutex);
  cv.wait(lock, [this, &p4_ids]() -> bool {
      return (read_cnt == 0) &&
          !do_sets_intersect(p4_ids_busy.begin(), p4_ids_busy.end(),
                             p4_ids.begin(), p4_ids.end());
  });
  write_cnt++;
  p4_ids_busy.insert(p4_ids.begin(), p4_ids.end());

  return access;
}

AccessArbitration::WriteAccess
AccessArbitration::write_access(common::p4_id_t p4_id) {
  WriteAccess access(this);
  access.p4_ids.insert(p4_id);

  std::unique_lock<std::mutex> lock(mutex);
  cv.wait(lock, [this, p4_id]() -> bool {
      return (read_cnt == 0) && (p4_ids_busy.count(p4_id) == 0);
  });
  write_cnt++;
  p4_ids_busy.insert(p4_id);

  return access;
}

AccessArbitration::NoWriteAccess
AccessArbitration::no_write_access(common::p4_id_t p4_id) {
  NoWriteAccess access(this);
  access.p4_id = p4_id;

  std::unique_lock<std::mutex> lock(mutex);
  cv.wait(lock, [this, p4_id]() -> bool {
      return (p4_ids_busy.count(p4_id) == 0);
  });
  no_write_cnt++;
  p4_ids_busy.insert(p4_id);

  return access;
}

AccessArbitration::ReadAccess
AccessArbitration::read_access() {
  ReadAccess access(this);

  std::unique_lock<std::mutex> lock(mutex);
  cv.wait(lock, [this]() -> bool {
      return (write_cnt == 0);
  });
  read_cnt++;

  return access;
}

AccessArbitration::UniqueAccess
AccessArbitration::unique_access() {
  return UniqueAccess(mutex);
}

void
AccessArbitration::release_write_access(const WriteAccess &access) {
  std::unique_lock<std::mutex> lock(mutex);
  write_cnt--;
  for (auto p4_id : access.p4_ids) p4_ids_busy.erase(p4_id);
  cv.notify_all();
}

void
AccessArbitration::release_read_access() {
  std::unique_lock<std::mutex> lock(mutex);
  read_cnt--;
  cv.notify_all();
}

void
AccessArbitration::release_no_write_access(const NoWriteAccess &access) {
  std::unique_lock<std::mutex> lock(mutex);
  no_write_cnt--;
  p4_ids_busy.erase(access.p4_id);
  cv.notify_all();
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
