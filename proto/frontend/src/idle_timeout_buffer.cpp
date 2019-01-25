/* Copyright 2019-present Barefoot Networks, Inc.
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

#include "idle_timeout_buffer.h"

#include <PI/frontends/cpp/tables.h>

#include <chrono>
#include <future>
#include <memory>
#include <thread>

#include "match_key_helpers.h"
#include "report_error.h"
#include "table_info_store.h"
#include "task_queue.h"

namespace pi {

namespace fe {

namespace proto {

namespace p4v1 = ::p4::v1;

namespace {

namespace detail {

template <typename T> class Task : public TaskIface{
 public:
  explicit Task(T buffer)
      : buffer(buffer) { }

 protected:
  T buffer;
};

}  // namespace detail

using Task = detail::Task<IdleTimeoutBuffer *>;
// not used for now
// using ConstTask = detail::Task<const IdleTimeoutBuffer *>;

using EmptyPromise = std::promise<void>;

using p4_id_t = common::p4_id_t;

}  // namespace

class IdleTimeoutBuffer::TaskSendNotifications : public Task {
 public:
  explicit TaskSendNotifications(IdleTimeoutBuffer *buffer)
      : Task(buffer) { }

  void operator()() override {
    using Clock = std::chrono::steady_clock;
    auto &notifications = buffer->notifications;
    if (notifications.table_entry().empty() || !buffer->cb) return;
    notifications.set_timestamp(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now().time_since_epoch()).count());
    p4v1::StreamMessageResponse msg;
    msg.set_allocated_idle_timeout_notification(&notifications);
    buffer->cb(buffer->device_id, &msg, buffer->cookie);
    msg.release_idle_timeout_notification();
    notifications.Clear();
  }
};

IdleTimeoutBuffer::IdleTimeoutBuffer(device_id_t device_id,
                                     const TableInfoStore *table_info_store,
                                     int64_t max_buffering_ns)
    : device_id(device_id),
      table_info_store(table_info_store),
      max_buffering_ns(max_buffering_ns),
      task_queue(new IdleTimeoutTaskQueue()) {
  task_queue_thread = std::thread(
      &IdleTimeoutTaskQueue::execute, task_queue.get());
}

IdleTimeoutBuffer::~IdleTimeoutBuffer() {
  task_queue->stop();
  task_queue_thread.join();
}

// We assume that no notifications are received after the p4_change call
// completes. Note that p4_change is called after pi_update_device_start
// returns. Targets should take this into account and should not generate
// notifications for the old dataplane after pi_update_device_start returns.
// This guarantees that the stored p4info pointer is always valid.
Status
IdleTimeoutBuffer::p4_change(const pi_p4info_t *p4info) {
  class TaskP4Change : public Task {
   public:
    TaskP4Change(IdleTimeoutBuffer *buffer,
                 const pi_p4info_t *p4info,
                 EmptyPromise &promise)  // NOLINT(runtime/references)
        : Task(buffer), p4info(p4info), promise(promise) { }

    void operator()() override {
      // drain notifications for old P4
      TaskSendNotifications sender(buffer);
      sender();
      buffer->p4info = p4info;
      promise.set_value();
    }

   private:
    const pi_p4info_t *p4info;
    EmptyPromise &promise;
  };

  EmptyPromise promise;
  task_queue->execute_task(std::unique_ptr<TaskIface>(
      new TaskP4Change(this, p4info, promise)));
  promise.get_future().wait();
  RETURN_OK_STATUS();
}

void
IdleTimeoutBuffer::stream_message_response_register_cb(
    StreamMessageResponseCb cb, void *cookie) {
  class TaskRegisterCb : public Task {
   public:
    TaskRegisterCb(IdleTimeoutBuffer *buffer,
                   EmptyPromise &promise,  // NOLINT(runtime/references)
                   // NOLINTNEXTLINE(whitespace/operators)
                   StreamMessageResponseCb &&cb,
                   void *cookie)
        : Task(buffer), promise(promise), cb(std::move(cb)), cookie(cookie) { }

    void operator()() override {
      buffer->cb = std::move(cb);
      buffer->cookie = std::move(cookie);
      promise.set_value();
    }

   private:
    EmptyPromise &promise;
    StreamMessageResponseCb &&cb;
    void *cookie;
  };

  EmptyPromise promise;
  task_queue->execute_task(std::unique_ptr<TaskIface>(new TaskRegisterCb(
      this, promise, std::move(cb), cookie)));
  promise.get_future().wait();
}

void
IdleTimeoutBuffer::handle_notification(p4_id_t table_id,
                                       pi::MatchKey match_key) {
  class TaskHandleNotification : public Task {
   public:
    TaskHandleNotification(IdleTimeoutBuffer *buffer,
                           p4_id_t table_id,
                           pi::MatchKey match_key)
      : Task(buffer), table_id(table_id), match_key(std::move(match_key)) { }

    void operator()() override {
      auto &notifications = buffer->notifications;
      bool first_notification = notifications.table_entry().empty();
      auto *table_entry = notifications.add_table_entry();
      table_entry->set_table_id(table_id);
      {
        auto table_lock = buffer->table_info_store->lock_table(table_id);
        auto *entry_data = buffer->table_info_store->get_entry(
            table_id, match_key);
        if (entry_data == nullptr) {
          Logger::get()->error("Failed to locate match key from idle timeout "
                               "notification in table info store");
          notifications.mutable_table_entry()->RemoveLast();
          return;
        }
        table_entry->set_controller_metadata(entry_data->controller_metadata);
        table_entry->set_idle_timeout_ns(entry_data->idle_timeout_ns);
      }
      // simple sanity check: we should not be generating notifications for
      // entries which don't age.
      if (table_entry->idle_timeout_ns() == 0) {
        notifications.mutable_table_entry()->RemoveLast();
        return;
      }
      auto status = parse_match_key(
          buffer->p4info, table_id, match_key, table_entry);
      if (IS_ERROR(status)) {
        Logger::get()->error(
            "Failed to convert match key "
            "when generating idle timeout notification");
          notifications.mutable_table_entry()->RemoveLast();
        return;
      }
      if (first_notification) {
        buffer->task_queue->execute_task_in(
            std::unique_ptr<TaskIface>(new TaskSendNotifications(buffer)),
            std::chrono::nanoseconds(buffer->max_buffering_ns));
      }
    }

   private:
    p4_id_t table_id;
    pi::MatchKey match_key;
  };

  // non-blocking
  size_t count = task_queue->execute_task_or_drop(
      std::unique_ptr<TaskIface>(
          new TaskHandleNotification(this, table_id, std::move(match_key))),
      max_queue_size);
  if (count == 0) {
    Logger::get()->debug(
        "Dropping idle time notification for table {} because queue is full",
        table_id);
    drop_count++;
  }
}

}  // namespace proto

}  // namespace fe

}  // namespace pi
