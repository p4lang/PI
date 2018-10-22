/* Copyright 2018-present Barefoot Networks, Inc.
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

#ifndef SRC_TASK_QUEUE_H_
#define SRC_TASK_QUEUE_H_

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

// A generic asynchronous task queue implementations. Tasks have to implement
// the TaskIface interface which means that unfortunately at the moment we
// cannot register lambdas.

namespace pi {

namespace fe {

namespace proto {

class TaskIface {
 public:
  virtual ~TaskIface() = default;

  virtual void operator()() = 0;

  virtual bool cancelled() { return false; }
};

class CancellableTask : public TaskIface {
 public:
  void cancel() { cancelled_ = true; }

  bool cancelled() override { return cancelled_; }

 private:
  std::atomic<bool> cancelled_{false};
};

template <typename Clock>
class TaskQueue {
 public:
  TaskQueue() = default;

  void execute() {
    while (true) {
      std::unique_ptr<TaskIface> task;
      {
        Lock lock(m);
        while (!stop_processing &&
               (queue.empty() || queue.top().execute_tp > Clock::now())) {
          if (queue.empty())
            cv.wait(lock);
          else
            cv.wait_until(lock, queue.top().execute_tp);
        }
        if (stop_processing) return;
        // http://stackoverflow.com/questions/20149471/move-out-element-of-std-priority-queue-in-c11
        task = std::move(const_cast<QueueE &>(queue.top()).task);
        queue.pop();
      }
      if (!task->cancelled()) (*task)();
    }
  }

  void stop() {
    Lock lock(m);
    stop_processing = true;
    cv.notify_one();
  }

  void execute_task(std::unique_ptr<TaskIface> task) {
    push_task(std::move(task), Clock::now());
  }

  void execute_task_at(std::unique_ptr<TaskIface> task,
                       const typename Clock::time_point &tp) {
    push_task(std::move(task), tp);
  }

  template <typename Rep, typename Period>
  void execute_task_in(std::unique_ptr<TaskIface> task,
                       const std::chrono::duration<Rep, Period> &duration) {
    push_task(std::move(task), Clock::now() + duration);
  }

  template <typename Rep, typename Period>
  void execute_periodic_task(
      std::unique_ptr<TaskIface> task,
      const std::chrono::duration<Rep, Period> &interval,
      bool wait_first = false) {
    struct PeriodicTask : public TaskIface {
      PeriodicTask(TaskQueue *tqueue,
                   std::unique_ptr<TaskIface> user_task,
                   const std::chrono::duration<Rep, Period> &interval)
          : tqueue(tqueue),
            user_task(std::move(user_task)),
            interval(interval) { }

      void operator()() override {
        (*user_task)();
        tqueue->execute_periodic_task(std::move(user_task), interval, true);
      }

      bool cancelled() override {
        return user_task->cancelled();
      }

      TaskQueue *tqueue;
      std::unique_ptr<TaskIface> user_task;
      const std::chrono::duration<Rep, Period> interval;
    };

    std::unique_ptr<TaskIface> timer_task(new PeriodicTask(
        this, std::move(task), interval));
    if (wait_first)
      push_task(std::move(timer_task), Clock::now() + interval);
    else
      push_task(std::move(timer_task), Clock::now());
  }

  TaskQueue(const TaskQueue &) = delete;
  TaskQueue &operator=(const TaskQueue &) = delete;
  TaskQueue(TaskQueue &&) = delete;
  TaskQueue &operator=(TaskQueue &&) = delete;

 private:
  using Lock = std::unique_lock<std::mutex>;

  struct QueueE {
    QueueE(std::unique_ptr<TaskIface> task,
           const typename Clock::time_point &execute_tp)
        : task(std::move(task)), execute_tp(execute_tp) { }

    std::unique_ptr<TaskIface> task;
    typename Clock::time_point execute_tp;
  };

  struct QueueEComp {
    bool operator()(const QueueE &lhs, const QueueE &rhs) const {
      return lhs.execute_tp > rhs.execute_tp;
    }
  };

  template <typename Duration>
  void push_task(std::unique_ptr<TaskIface> task,
                 const std::chrono::time_point<Clock, Duration> &tp) {
    Lock lock(m);
    queue.emplace(std::move(task), tp);
    cv.notify_one();
  }

  bool stop_processing{false};
  std::priority_queue<QueueE, std::vector<QueueE>, QueueEComp> queue;
  mutable std::mutex m;
  mutable std::condition_variable cv;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // SRC_TASK_QUEUE_H_
