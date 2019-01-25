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

#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

#include "src/task_queue.h"

namespace pi {
namespace proto {
namespace testing {
namespace {

using pi::fe::proto::TaskIface;
using pi::fe::proto::CancellableTask;
using Clock = std::chrono::steady_clock;
using TaskQueue = pi::fe::proto::TaskQueue<Clock>;

class TaskQueueTest : public ::testing::Test {
 public:
  TaskQueueTest() { }

  void SetUp() override {
    task_queue_thread = std::thread(&TaskQueue::execute, &task_queue);
  }

  void TearDown() override {
    task_queue.stop();
    task_queue_thread.join();
  }

 protected:
  TaskQueue task_queue;
  std::thread task_queue_thread;
};

struct Task : public TaskIface {
  Task(std::promise<int> &promise, int v)  // NOLINT(runtime/references)
      : promise(promise), v(v) { }

  void operator()() override {
    promise.set_value(v);
  }

  std::promise<int> &promise;
  int v;
};

TEST_F(TaskQueueTest, ImmediateTask) {
  std::promise<int> promise;
  auto future = promise.get_future();
  ASSERT_EQ(task_queue.execute_task(
      std::unique_ptr<TaskIface>(new Task(promise, 99))), 1u);
  future.wait();
  EXPECT_EQ(future.get(), 99);
}

TEST_F(TaskQueueTest, TaskIn) {
  std::promise<int> promise;
  auto future = promise.get_future();
  ASSERT_EQ(task_queue.execute_task_in(
      std::unique_ptr<TaskIface>(new Task(promise, 99)),
      std::chrono::milliseconds(200)), 1u);
  auto start = Clock::now();
  future.wait();
  auto end = Clock::now();
  EXPECT_EQ(future.get(), 99);
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      end - start).count();
  EXPECT_GT(elapsed, 100);
  EXPECT_LT(elapsed, 300);
}

TEST_F(TaskQueueTest, TaskAt) {
  std::promise<int> promise;
  auto future = promise.get_future();
  auto start = Clock::now();
  ASSERT_EQ(task_queue.execute_task_at(
      std::unique_ptr<TaskIface>(new Task(promise, 99)),
      start + std::chrono::milliseconds(200)), 1u);
  future.wait();
  auto end = Clock::now();
  EXPECT_EQ(future.get(), 99);
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      end - start).count();
  EXPECT_GT(elapsed, 100);
  EXPECT_LT(elapsed, 300);
}

struct PeriodicTask : public CancellableTask {
  explicit PeriodicTask(std::vector<Clock::time_point> *tps)
      : tps(tps) { }

  void operator()() override {
    tps->push_back(Clock::now());
  }

  std::vector<Clock::time_point> *tps;
};

TEST_F(TaskQueueTest, PeriodicTask) {
  std::vector<Clock::time_point> tps;
  auto *task = new PeriodicTask(&tps);
  ASSERT_EQ(task_queue.execute_periodic_task(
      std::unique_ptr<TaskIface>(task), std::chrono::milliseconds(200)), 1u);
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  task->cancel();
  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  EXPECT_EQ(tps.size(), 3u);
}

TEST_F(TaskQueueTest, ReorderTasks) {
  struct Task : public TaskIface {
    // NOLINTNEXTLINE(runtime/references)
    explicit Task(std::promise<Clock::time_point> &promise)
        : promise(promise) { }

    void operator()() override {
      promise.set_value(Clock::now());
    }

    std::promise<Clock::time_point> &promise;
  };
  std::promise<Clock::time_point> promise1;
  auto future1 = promise1.get_future();
  ASSERT_EQ(task_queue.execute_task_in(
      std::unique_ptr<TaskIface>(new Task(promise1)),
      std::chrono::milliseconds(200)), 1u);
  std::promise<Clock::time_point> promise2;
  auto future2 = promise2.get_future();
  ASSERT_EQ(task_queue.execute_task(
      std::unique_ptr<TaskIface>(new Task(promise2))), 1u);
  future1.wait();
  future2.wait();
  EXPECT_LT(future2.get(), future1.get());
}

TEST_F(TaskQueueTest, ExecuteTaskOrDrop) {
  static constexpr size_t max_size = 100;
  task_queue.stop();
  size_t count = 0;
  std::promise<int> promise;
  for (size_t i = 0; i < max_size; i++) {
    count += task_queue.execute_task_or_drop(
        std::unique_ptr<TaskIface>(new Task(promise, 99)), max_size);
  }
  EXPECT_EQ(count, max_size);
  EXPECT_EQ(task_queue.execute_task_or_drop(
      std::unique_ptr<TaskIface>(new Task(promise, 99)), max_size), 0u);
}

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
