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

#include <grpc++/grpc++.h>

#include <gtest/gtest.h>

#include <gnmi/gnmi.grpc.pb.h>

#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "gnmi.h"

using grpc::Server;
using grpc::ServerBuilder;

using grpc::ClientContext;
using grpc::Status;
using grpc::StatusCode;

namespace pi {
namespace proto {
namespace testing {
namespace {

// Cannot use TestServer class from utils because we need to be able to test
// both gNMI services even when sysrepo is present. The default server (started
// by PIGrpcServerRunAddr) will default to sysrepo if it is present.

class GnmiServer {
 public:
  explicit GnmiServer(std::unique_ptr<gnmi::gNMI::Service> gnmi_service)
      : gnmi_service(std::move(gnmi_service)) {
    builder.AddListeningPort(
        bind_any_addr, grpc::InsecureServerCredentials(), &server_port);
    builder.RegisterService(this->gnmi_service.get());
    server = builder.BuildAndStart();
  }

  ~GnmiServer() {
    server->Shutdown();
  }

  std::string bind_addr() const {
    return std::string("0.0.0.0:") + std::to_string(server_port);
  }

 private:
  static constexpr char bind_any_addr[] = "[::]:0";
  std::unique_ptr<gnmi::gNMI::Service> gnmi_service;
  ServerBuilder builder;
  std::unique_ptr<Server> server;
  int server_port;
};

constexpr char GnmiServer::bind_any_addr[];

class TestGNMI : public ::testing::Test {
 protected:
  TestGNMI()
      : gnmi_channel(grpc::CreateChannel(
            server->bind_addr(), grpc::InsecureChannelCredentials())),
        gnmi_stub(gnmi::gNMI::NewStub(gnmi_channel)) { }

  static void setup_server(std::unique_ptr<gnmi::gNMI::Service> gnmi_service) {
    server = new GnmiServer(std::move(gnmi_service));
  }

  static void teardown_server() {
    delete server;
  }

  static GnmiServer *server;

  std::shared_ptr<grpc::Channel> gnmi_channel;
  std::unique_ptr<gnmi::gNMI::Stub> gnmi_stub;
};

GnmiServer *TestGNMI::server = nullptr;

class TestGNMIDummy : public TestGNMI {
 protected:
  static void SetUpTestCase() {
    setup_server(pi::server::make_gnmi_service_dummy());
  }

  static void TearDownTestCase() {
    teardown_server();
  }
};

// check that Subscribe stream stays open, even though nothing is implemented
// yet
TEST_F(TestGNMIDummy, SubscribeStaysOpen) {
  gnmi::SubscribeRequest req;
  gnmi::SubscribeResponse rep;
  ClientContext context;
  auto stream = gnmi_stub->Subscribe(&context);
  EXPECT_TRUE(stream->WritesDone());
  auto status = stream->Finish();
  EXPECT_TRUE(status.ok());
}

TEST_F(TestGNMIDummy, SubscribeErrorOnWrite) {
  gnmi::SubscribeRequest req;
  gnmi::SubscribeResponse rep;
  ClientContext context;
  auto stream = gnmi_stub->Subscribe(&context);
  EXPECT_TRUE(stream->Write(req));
  EXPECT_TRUE(stream->WritesDone());
  auto status = stream->Finish();
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(StatusCode::UNIMPLEMENTED, status.error_code());
}

#ifdef WITH_SYSREPO

extern "C" {
#include <sysrepo.h>
#include <sysrepo/values.h>
}

class SysrepoSession {
 public:
  ~SysrepoSession() {
    if (sess != nullptr) sr_session_stop(sess);
    if (conn != nullptr) sr_disconnect(conn);
  }

  bool open(const std::string &app_name) {
    int rc = SR_ERR_OK;
    rc = sr_connect(app_name.c_str(), SR_CONN_DEFAULT, &conn);
    if (rc != SR_ERR_OK) return false;
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sess);
    return rc == SR_ERR_OK;
  }

  sr_session_ctx_t *get() const { return sess; }

 private:
  sr_conn_ctx_t *conn{nullptr};
  sr_session_ctx_t *sess{nullptr};
};

struct Event {
  std::string xpath;
  sr_change_oper_t oper;
  std::string new_v_str;
};

class SysrepoEventQueue {
 public:
  void push_front(Event &&e) {
    Lock lock(q_mutex);
    queue.push_front(std::move(e));
    lock.unlock();
    q_not_empty.notify_one();
  }

  bool pop_back(Event *pE) {
    Lock lock(q_mutex);
    q_not_empty.wait(lock, [this]{ return !is_not_empty(); });
    *pE = std::move(queue.back());
    queue.pop_back();
    return true;
  }

  bool pop_back(Event *pE, const std::chrono::milliseconds &max_wait) {
    Lock lock(q_mutex);
    auto success = q_not_empty.wait_for(
        lock, max_wait, [this]{ return is_not_empty(); });
    if (!success) return false;
    *pE = std::move(queue.back());
    queue.pop_back();
    return true;
  }

  size_t size() const {
    Lock lock(q_mutex);
    return queue.size();
  }

  bool empty() const {
    Lock lock(q_mutex);
    return queue.empty();
  }

  void clear() {
    Lock lock(q_mutex);
    queue.clear();
  }

 private:
  bool is_not_empty() const { return queue.size() > 0; }

  using Lock = std::unique_lock<std::mutex>;
  std::deque<Event> queue;
  mutable std::mutex q_mutex;
  mutable std::condition_variable q_not_empty;
};

#define XPATH_MAX_LEN 256
#define VAL_STR_MAX_LEN 256

int module_change_cb(sr_session_ctx_t *session, const char *module_name,
                     sr_notif_event_t event, void *private_ctx) {
  (void) event;

  sr_change_iter_t *it = nullptr;
  int rc = SR_ERR_OK;
  sr_change_oper_t oper;
  sr_val_t *old_value = nullptr;
  sr_val_t *new_value = nullptr;
  char val_str[VAL_STR_MAX_LEN] = {};

  assert(event == SR_EV_APPLY);  // we subscribed with SR_SUBSCR_APPLY_ONLY

  std::string change_path("/");
  change_path.append(module_name).append(":*");

  rc = sr_get_changes_iter(session, change_path.c_str(), &it);
  assert(rc == SR_ERR_OK);

  auto *event_queue = static_cast<SysrepoEventQueue *>(private_ctx);

  while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value))
         == SR_ERR_OK) {
    if (new_value->type >= SR_LEAF_EMPTY_T && !new_value->dflt) {
      sr_val_to_buff(new_value, val_str, sizeof(val_str));
      std::cout << "CHANGE for " << new_value->xpath << ": " << val_str << "\n";
      event_queue->push_front(
          {std::string(new_value->xpath), oper, std::string(val_str)});
    }
    sr_free_val(old_value);
    sr_free_val(new_value);
  }

  sr_free_change_iter(it);

  return SR_ERR_OK;
}

#undef XPATH_MAX_LEN
#undef VAL_STR_MAX_LEN

class SysrepoSubscriber {
 public:
  SysrepoSubscriber(const std::string &module_name, const std::string &app_name)
      : module_name(module_name), app_name(app_name) { }

  ~SysrepoSubscriber() {
    if (subscription != nullptr) {
      sr_unsubscribe(session.get(), subscription);
      subscription = nullptr;
    }
  }

  bool subscribe(SysrepoEventQueue *event_queue) {
    session.open(app_name);
    int rc = sr_module_change_subscribe(
        session.get(), module_name.c_str(), module_change_cb,
        static_cast<void *>(event_queue), 0, SR_SUBSCR_APPLY_ONLY,
        &subscription);
    return rc == SR_ERR_OK;
  }

 private:
  std::string module_name;
  std::string app_name;
  SysrepoSession session;
  sr_subscription_ctx_t *subscription{nullptr};
};

class GNMIPathBuilder {
 public:
  explicit GNMIPathBuilder(gnmi::Path *path)
      : path(path) { }

  GNMIPathBuilder &append(const std::string &name,
                          const std::map<std::string, std::string> &keys = {}) {
    auto *e = path->add_elem();
    e->set_name(name);
    e->mutable_key()->insert(keys.begin(), keys.end());
    return *this;
  }

 private:
  gnmi::Path *path;
};

// We could find a way to mock sysrepo for this. However, we are really trying
// to verify end-to-end functionality here. We need to make sure that we are
// using the sysrepo client library correctly and that sysrepo is doing the
// right thing, as it is not very mature yet.

// The test assumes that openconfig-interfaces is implemented in sysrepo

class TestGNMISysrepo : public TestGNMI {
 protected:
  TestGNMISysrepo()
      : sub("openconfig-interfaces", "sub") { }

  static void SetUpTestCase() {
    setup_server(pi::server::make_gnmi_service_sysrepo());
  }

  static void TearDownTestCase() {
    teardown_server();
  }

  void SetUp() override {
    ASSERT_TRUE(session.open("test"));
    ASSERT_TRUE(cleanup_data_tree());
    ASSERT_TRUE(sub.subscribe(&event_queue));
  }

  void TearDown() override {
    ASSERT_TRUE(cleanup_data_tree());
  }

  bool cleanup_data_tree() const {
    int rc = sr_delete_item(
        session.get(), "/openconfig-interfaces:*", SR_EDIT_DEFAULT);
    return rc == SR_ERR_OK;
  }

  gnmi::SetRequest create_iface(const std::string &name) {
    gnmi::SetRequest req;
    GNMIPathBuilder pb(req.mutable_prefix());
    pb.append("interfaces").append("interface", {{"name", name}})
        .append("config");
    {
      auto *update = req.add_update();
      GNMIPathBuilder pb(update->mutable_path());
      pb.append("name");
      update->mutable_val()->set_string_val(name);
    }
    {
      auto *update = req.add_update();
      GNMIPathBuilder pb(update->mutable_path());
      pb.append("type");
      update->mutable_val()->set_string_val("iana-if-type:ethernetCsmacd");
    }
    return req;
  }

  std::unordered_map<std::string, Event> get_events(size_t num_events) {
    std::unordered_map<std::string, Event> events;
    for (size_t i = 0; i < num_events; i++) {
      Event event;
      if (!event_queue.pop_back(&event, std::chrono::milliseconds(500)))
        break;
      events.emplace(event.xpath, std::move(event));
    }
    return events;
  }

  bool no_more_events(
      std::chrono::milliseconds wait = std::chrono::milliseconds(200)) {
    std::this_thread::sleep_for(wait);
    return event_queue.empty();
  }

  SysrepoSession session{};
  // event_queue needs to be constructed before sub and destroyed after
  SysrepoEventQueue event_queue;
  SysrepoSubscriber sub;
};

TEST_F(TestGNMISysrepo, Set) {
  const std::string iface_name("eth0");
  auto req = create_iface(iface_name);
  gnmi::SetResponse rep;
  ClientContext context;
  auto status = gnmi_stub->Set(&context, req, &rep);
  EXPECT_TRUE(status.ok());
  // name, config/name, config/type
  size_t num_expected_events = 3u;
  auto events = get_events(num_expected_events);
  ASSERT_EQ(events.size(), num_expected_events);
  auto check_event = [&events](const Event &expected_event) {
    auto it = events.find(expected_event.xpath);
    ASSERT_NE(it, events.end());
    const auto &event = it->second;
    EXPECT_EQ(event.oper, expected_event.oper);
    EXPECT_EQ(event.new_v_str, expected_event.new_v_str);
  };
  check_event({
      "/openconfig-interfaces:interfaces/interface[name='eth0']/name",
      SR_OP_CREATED, iface_name});
  check_event({
      "/openconfig-interfaces:interfaces/interface[name='eth0']/config/name",
      SR_OP_CREATED, iface_name});
  check_event({
      "/openconfig-interfaces:interfaces/interface[name='eth0']/config/type",
      SR_OP_CREATED, "iana-if-type:ethernetCsmacd"});
  EXPECT_TRUE(no_more_events());
}

#endif  // WITH_SYSREPO

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
