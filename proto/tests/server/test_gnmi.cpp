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

#include <boost/optional.hpp>

#include <grpc++/grpc++.h>

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "gnmi/gnmi.grpc.pb.h"

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

bool operator ==(const Event &e1, const Event &e2) {
  return (e1.xpath == e2.xpath) &&
      (e1.oper == e2.oper) &&
      (e1.new_v_str == e2.new_v_str);
}

std::ostream &operator <<(std::ostream &os, const Event &e) {
  os << "Event(xpath=" << e.xpath << ", oper=" << e.oper
     << ", new_val=" << e.new_v_str << ")";
  return os;
}

std::ostream &operator <<(std::ostream &os, const boost::optional<Event> &e) {
  if (e.is_initialized())
    os << e.get();
  else
    os << "NONE";
  return os;
}

class SysrepoEventQueue {
 public:
  void push_front(Event &&e) {
    Lock lock(q_mutex);
    // create queue for xpath if doesn't exist yet
    queues[e.xpath].push_front(std::move(e));
    lock.unlock();
    q_not_empty.notify_all();
  }

  // Event *pE needs to have xpath set
  bool pop_back(Event *pE) {
    Lock lock(q_mutex);
    q_not_empty.wait(lock, [this, pE]{ return !is_not_empty(pE->xpath); });
    auto &queue = queues.at(pE->xpath);
    *pE = std::move(queue.back());
    queue.pop_back();
    remove_if_empty(pE->xpath);
    return true;
  }

  // Event *pE needs to have xpath set
  bool pop_back(Event *pE, const std::chrono::milliseconds &max_wait) {
    Lock lock(q_mutex);
    auto success = q_not_empty.wait_for(
        lock, max_wait, [this, pE]{ return is_not_empty(pE->xpath); });
    if (!success) return false;
    auto &queue = queues.at(pE->xpath);
    *pE = std::move(queue.back());
    queue.pop_back();
    remove_if_empty(pE->xpath);
    return true;
  }

  bool pop_back_any(Event *pE) {
    Lock lock(q_mutex);
    q_not_empty.wait(lock, [this]{ return !is_not_empty(); });
    auto &queue = queues.begin()->second;
    *pE = std::move(queue.back());
    queue.pop_back();
    remove_if_empty(pE->xpath);
    return true;
  }

  bool pop_back_any(Event *pE, const std::chrono::milliseconds &max_wait) {
    Lock lock(q_mutex);
    auto success = q_not_empty.wait_for(
        lock, max_wait, [this]{ return !is_not_empty(); });
    if (!success) return false;
    auto &queue = queues.begin()->second;
    *pE = std::move(queue.back());
    queue.pop_back();
    remove_if_empty(pE->xpath);
    return true;
  }

  bool empty() const {
    Lock lock(q_mutex);
    return queues.empty();
  }

  void clear() {
    Lock lock(q_mutex);
    queues.clear();
  }

 private:
  bool is_not_empty(const std::string &xpath) const {
    auto it = queues.find(xpath);
    return (it != queues.end()) && !it->second.empty();
  }

  bool is_not_empty() const {
    return !queues.empty();
  }

  void remove_if_empty(const std::string &xpath) {
    auto it = queues.find(xpath);
    if (it == queues.end()) return;
    if (it->second.empty()) queues.erase(it);
  }

  using Lock = std::unique_lock<std::mutex>;
  using Queue = std::deque<Event>;
  // key is xpath
  std::unordered_map<std::string, Queue> queues;
  mutable std::mutex q_mutex;
  mutable std::condition_variable q_not_empty;
};

#define VAL_STR_MAX_LEN 256

// Just a toy version of a validation function, which fails only if we try to
// create an interface which doesn't have the correct type (ethernet)
int module_change_verify(sr_session_ctx_t *session, const char *module_name,
                         void *private_ctx) {
  (void) private_ctx;

  sr_change_iter_t *it = nullptr;
  int rc = SR_ERR_OK;
  sr_change_oper_t oper;
  sr_val_t *old_value = nullptr;
  sr_val_t *new_value = nullptr;
  char val_str[VAL_STR_MAX_LEN] = {};
  bool error = false;

  std::string change_path("/");
  change_path.append(module_name).append(":*");

  rc = sr_get_changes_iter(session, change_path.c_str(), &it);
  assert(rc == SR_ERR_OK);

  while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value))
         == SR_ERR_OK) {
    if (oper != SR_OP_CREATED && oper != SR_OP_MODIFIED) continue;
    if (new_value->type < SR_LEAF_EMPTY_T || new_value->dflt) continue;
    std::string xpath(new_value->xpath);
    std::string suffix("config/type");
    if (xpath.substr(xpath.size() - suffix.size(), xpath.size()) == suffix) {
      sr_val_to_buff(new_value, val_str, sizeof(val_str));
      if (std::string(val_str) != "iana-if-type:ethernetCsmacd") {
        error = true;
        sr_set_error(session, "Invalid interface type", new_value->xpath);
      }
    }
    sr_free_val(old_value);
    sr_free_val(new_value);
    if (error) break;
  }

  sr_free_change_iter(it);

  return error ? SR_ERR_UNSUPPORTED : SR_ERR_OK;
}

int module_change_apply(sr_session_ctx_t *session, const char *module_name,
                        void *private_ctx) {
  sr_change_iter_t *it = nullptr;
  int rc = SR_ERR_OK;
  sr_change_oper_t oper;
  sr_val_t *old_value = nullptr;
  sr_val_t *new_value = nullptr;
  char val_str[VAL_STR_MAX_LEN] = {};

  std::string change_path("/");
  change_path.append(module_name).append(":*");

  rc = sr_get_changes_iter(session, change_path.c_str(), &it);
  assert(rc == SR_ERR_OK);

  auto *event_queue = static_cast<SysrepoEventQueue *>(private_ctx);

  while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value))
         == SR_ERR_OK) {
    if (oper == SR_OP_CREATED || oper == SR_OP_MODIFIED) {
      if (new_value->type >= SR_LEAF_EMPTY_T && !new_value->dflt) {
        sr_val_to_buff(new_value, val_str, sizeof(val_str));
        std::cout << "WROTE " << new_value->xpath << ": " << val_str << "\n";
        event_queue->push_front(
            {std::string(new_value->xpath), oper, std::string(val_str)});
      }
    } else if (oper == SR_OP_DELETED) {
      assert(new_value == nullptr);
      if (old_value->type >= SR_LEAF_EMPTY_T && !old_value->dflt) {
        std::cout << "DELETE " << old_value->xpath << "\n";
        event_queue->push_front(
            {std::string(old_value->xpath), oper, ""});
      }
    }
    sr_free_val(old_value);
    sr_free_val(new_value);
  }

  sr_free_change_iter(it);

  return SR_ERR_OK;
}

int module_change_cb(sr_session_ctx_t *session, const char *module_name,
                     sr_notif_event_t event, void *private_ctx) {
  if (event == SR_EV_VERIFY)
    return module_change_verify(session, module_name, private_ctx);
  if (event == SR_EV_APPLY)
    return module_change_apply(session, module_name, private_ctx);
  return SR_ERR_OK;
}

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
    // SR_SUBSCR_NO_ABORT_FOR_REFUSED_CFG: The subscriber will not receive
    // SR_EV_ABORT if he returns an error in verify phase (if the commit is
    // refused by other verifier SR_EV_ABORT will be delivered).
    int rc = sr_module_change_subscribe(
        session.get(), module_name.c_str(), module_change_cb,
        static_cast<void *>(event_queue), 0, SR_SUBSCR_NO_ABORT_FOR_REFUSED_CFG,
        &subscription);
    return rc == SR_ERR_OK;
  }

 private:
  std::string module_name;
  std::string app_name;
  SysrepoSession session;
  sr_subscription_ctx_t *subscription{nullptr};
};

int data_provider_cb(const char *xpath, sr_val_t **values, size_t *values_cnt,
                     uint64_t request_id, void *private_ctx) {
  (void) request_id;
  (void) private_ctx;
  int rc = SR_ERR_OK;
  *values_cnt = 1u;
  sr_val_t *varray = nullptr;
  rc = sr_new_values(*values_cnt, &varray);
  if (rc != SR_ERR_OK) return rc;
  sr_val_t *v = &varray[0];
  sr_val_set_xpath(v, xpath);
  sr_val_set_str_data(v, SR_IDENTITYREF_T, "iana-if-type:ethernetCsmacd");
  *values = varray;
  return rc;
}

// The openconfig-if-ethernet augment for openconfig-interfaces has the
// following when condition:
// when "oc-if:state/oc-if:type = 'ift:ethernetCsmacd'" { ...
// As a result, we need an operational state provider to ensure that we can see
// data nodes in the augment.
// ACTUALLY, IT SEEMS THAT THE OPENCONFIG YANG MODEL IS NOT CORRECT. "WHEN"
// STATEMENTS IN CONFIG NODES CANNOT REFER TO STATE DATA.
// SEE https://github.com/openconfig/public/issues/108
class SysrepoStateProvider {
 public:
  explicit SysrepoStateProvider(const std::string &app_name)
      : app_name(app_name) { }

  ~SysrepoStateProvider() {
    if (subscription != nullptr) {
      sr_unsubscribe(session.get(), subscription);
      subscription = nullptr;
    }
  }

  bool subscribe() {
    session.open(app_name);
    int rc = sr_dp_get_items_subscribe(
        session.get(), "/openconfig-interfaces:interfaces/interface/state/type",
        data_provider_cb, nullptr,
        SR_SUBSCR_DEFAULT, &subscription);
    return rc == SR_ERR_OK;
  }

 private:
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
    if (rc != SR_ERR_OK) return false;
    rc = sr_commit(session.get());
    if (rc != SR_ERR_OK) return false;
    return true;
  }

  gnmi::SetRequest create_iface_req(const std::string &name) {
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

  Status create_iface(const std::string &name) {
    auto req = create_iface_req(name);
    gnmi::SetResponse rep;
    ClientContext context;
    return gnmi_stub->Set(&context, req, &rep);
  }

  bool no_more_events(
      std::chrono::milliseconds wait = std::chrono::milliseconds(200)) {
    std::this_thread::sleep_for(wait);
    return event_queue.empty();
  }

  boost::optional<Event> wait_for_event(const std::string &xpath) {
    Event event;
    event.xpath = xpath;
    if (!event_queue.pop_back(&event, std::chrono::milliseconds(500)))
      return boost::none;
    return event;
  }

  size_t consume_events(size_t expected_num_events) {
    for (size_t i = 0; i < expected_num_events; i++) {
      Event event;
      if (!event_queue.pop_back(&event, std::chrono::milliseconds(500)))
        return i;
    }
    return expected_num_events;
  }

  void check_event(const Event &expected_event) {
    EXPECT_EQ(wait_for_event(expected_event.xpath), expected_event);
  }

  void check_create_iface_events(const std::string &name) {
    auto xpath = [name](const std::string &suffix) {
      std::string path("/openconfig-interfaces:interfaces/interface");
      path.append("[name='").append(name).append("']/").append(suffix);
      return path;
    };

    check_event({xpath("name"), SR_OP_CREATED, name});
    check_event({xpath("config/name"), SR_OP_CREATED, name});
    check_event(
        {xpath("config/type"), SR_OP_CREATED, "iana-if-type:ethernetCsmacd"});
  }

  // only supports basic paths without '...' or '*'
  // works for all paths returned by a subscription
  std::string gNMI_path_to_XPath(const gnmi::Path &prefix,
                                 const gnmi::Path &path) const {
    std::string xpath("/openconfig-interfaces:");
    auto process_path = [&xpath](const gnmi::Path &p) {
      for (const auto &elem : p.elem()) {
        xpath.append(elem.name());
        for (const auto &p : elem.key())
          xpath.append("[" + p.first + "='" + p.second + "']");
        xpath.append("/");
      }
    };
    process_path(prefix);
    process_path(path);
    xpath.pop_back();
    return xpath;
  }

  std::string find_update(const gnmi::Notification &notification,
                          const std::string &iface_name,
                          const std::string &suffix) {
    const auto &updates = notification.update();
    std::string expected_xpath("/openconfig-interfaces:interfaces/interface");
    expected_xpath.append("[name='").append(iface_name).append("']/")
        .append(suffix);
    for (const auto &update : updates) {
      auto xpath = gNMI_path_to_XPath(notification.prefix(), update.path());
      if (xpath == expected_xpath) return update.val().string_val();
    }
    return "";  // use boost::optional instead ?
  }

  static constexpr char iface_type[] = "iana-if-type:ethernetCsmacd";

  SysrepoSession session{};
  // event_queue needs to be constructed before sub and destroyed after
  SysrepoEventQueue event_queue;
  SysrepoSubscriber sub;
};

constexpr char TestGNMISysrepo::iface_type[];

TEST_F(TestGNMISysrepo, Create) {
  const std::string iface_name("eth0");
  EXPECT_TRUE(create_iface(iface_name).ok());
  check_create_iface_events(iface_name);
  EXPECT_TRUE(no_more_events());
}

TEST_F(TestGNMISysrepo, CreateUpdateAndDelete) {
  const std::string iface_name("eth0");
  EXPECT_TRUE(create_iface(iface_name).ok());
  check_create_iface_events(iface_name);
  const std::string mtu_path(
      "/openconfig-interfaces:interfaces/interface[name='eth0']/config/mtu");

  auto set_mtu = [&mtu_path, &iface_name, this](unsigned int mtu) {
    gnmi::SetRequest req;
    auto *update = req.add_update();
    GNMIPathBuilder pb(update->mutable_path());
    pb.append("interfaces").append("interface", {{"name", iface_name}})
        .append("config").append("mtu");
    update->mutable_val()->set_uint_val(mtu);

    gnmi::SetResponse rep;
    ClientContext context;
    auto status = gnmi_stub->Set(&context, req, &rep);
    return status;
  };

  set_mtu(1500);
  check_event({mtu_path, SR_OP_CREATED, "1500"});

  set_mtu(1000);
  check_event({mtu_path, SR_OP_MODIFIED, "1000"});

  {
    gnmi::SetRequest req;
    GNMIPathBuilder pb(req.add_delete_());
    pb.append("interfaces").append("interface", {{"name", iface_name}})
        .append("config").append("mtu");

    gnmi::SetResponse rep;
    ClientContext context;
    auto status = gnmi_stub->Set(&context, req, &rep);
    EXPECT_TRUE(status.ok());
  }

  check_event({mtu_path, SR_OP_DELETED, ""});

  EXPECT_TRUE(no_more_events());
}

TEST_F(TestGNMISysrepo, SubscribeOnce) {
  const std::string iface_name("eth0");
  EXPECT_TRUE(create_iface(iface_name).ok());
  check_create_iface_events(iface_name);

  gnmi::SubscribeRequest req;
  gnmi::SubscribeResponse rep;
  ClientContext context;
  auto stream = gnmi_stub->Subscribe(&context);
  auto *subList = req.mutable_subscribe();
  subList->set_mode(gnmi::SubscriptionList::ONCE);
  auto *sub = subList->add_subscription();
  GNMIPathBuilder pb(sub->mutable_path());
  pb.append("interfaces").append("interface").append("...");
  EXPECT_TRUE(stream->Write(req));
  EXPECT_TRUE(stream->WritesDone());

  EXPECT_TRUE(stream->Read(&rep));  // subscription response
  ASSERT_EQ(rep.response_case(), gnmi::SubscribeResponse::kUpdate);
  const auto &notification = rep.update();
  // name + config/name + config/type
  EXPECT_EQ(notification.update().size(), 3);
  EXPECT_EQ(find_update(notification, iface_name, "name"), iface_name);
  EXPECT_EQ(find_update(notification, iface_name, "config/name"), iface_name);
  EXPECT_EQ(find_update(notification, iface_name, "config/type"), iface_type);

  EXPECT_TRUE(stream->Read(&rep));  // EOM
  EXPECT_TRUE(rep.sync_response());

  auto status = stream->Finish();
  EXPECT_TRUE(status.ok());

  EXPECT_TRUE(no_more_events());
}

TEST_F(TestGNMISysrepo, GetLeaf) {
  const std::string iface_name("eth0");
  EXPECT_TRUE(create_iface(iface_name).ok());
  check_create_iface_events(iface_name);

  {
    gnmi::GetRequest req;
    gnmi::GetResponse rep;
    ClientContext context;
    {
      GNMIPathBuilder pb(req.add_path());
      pb.append("interfaces").append("interface", {{"name", iface_name}})
          .append("config").append("type");
    }
    {
      GNMIPathBuilder pb(req.add_path());
      pb.append("interfaces").append("interface", {{"name", iface_name}})
          .append("config").append("name");
    }
    req.set_type(gnmi::GetRequest::ALL);
    EXPECT_TRUE(gnmi_stub->Get(&context, req, &rep).ok());
    // gNMI spec: "The target MUST generate a Notification message for each path
    // specified in the client's GetRequest, and hence MUST NOT collapse data
    // from multiple paths into a single Notification within the response."
    ASSERT_EQ(rep.notification_size(), 2);
    ASSERT_EQ(rep.notification(0).update_size(), 1);
    EXPECT_EQ(find_update(rep.notification(0), iface_name, "config/type"),
              iface_type);
    ASSERT_EQ(rep.notification(1).update_size(), 1);
    EXPECT_EQ(find_update(rep.notification(1), iface_name, "config/name"),
              iface_name);
  }

  EXPECT_TRUE(no_more_events());
}

TEST_F(TestGNMISysrepo, GetContainer) {
  const std::string iface_name("eth0");
  EXPECT_TRUE(create_iface(iface_name).ok());
  check_create_iface_events(iface_name);

  {
    gnmi::GetRequest req;
    gnmi::GetResponse rep;
    ClientContext context;
    GNMIPathBuilder pb(req.add_path());
    pb.append("interfaces").append("interface").append("...");
    req.set_type(gnmi::GetRequest::ALL);
    EXPECT_TRUE(gnmi_stub->Get(&context, req, &rep).ok());
    ASSERT_EQ(rep.notification_size(), 1);
    const auto &notification = rep.notification(0);

    // TODO(antonin): should the GetRequest return an aggregate (in protobuf
    // format) once we support ygot-generated protobufs.
    ASSERT_EQ(notification.update_size(), 3);
    EXPECT_EQ(find_update(notification, iface_name, "name"), iface_name);
    EXPECT_EQ(find_update(notification, iface_name, "config/name"), iface_name);
    EXPECT_EQ(find_update(notification, iface_name, "config/type"), iface_type);
  }

  EXPECT_TRUE(no_more_events());
}

TEST_F(TestGNMISysrepo, Augmentation) {
  SysrepoStateProvider state_provider("state_provider");
  ASSERT_TRUE(state_provider.subscribe());

  const std::string iface_name("eth0");
  EXPECT_TRUE(create_iface(iface_name).ok());
  check_create_iface_events(iface_name);

  gnmi::SetRequest req;
  auto *update = req.add_update();
  GNMIPathBuilder pb(update->mutable_path());
  // TODO(antonin): according to the gNMI spec, we should not have to specify
  // the module name for the augment, but we do not support this yet in the
  // server
  pb.append("interfaces").append("interface", {{"name", iface_name}})
      .append("openconfig-if-ethernet:ethernet")
      .append("config").append("port-speed");
  update->mutable_val()->set_string_val("SPEED_100GB");

  gnmi::SetResponse rep;
  ClientContext context;
  auto status = gnmi_stub->Set(&context, req, &rep);
  EXPECT_TRUE(status.ok());

  std::string port_speed_path(
      "/openconfig-interfaces:interfaces/interface[name='eth0']/");
  port_speed_path.append("openconfig-if-ethernet:ethernet/config/port-speed");

  // openconfig-if-ethernet seems to be necessart after updating sysrepo (&
  // libyang) to 0.7.5
  // check_event({port_speed_path, SR_OP_CREATED, "SPEED_100GB"});
  check_event(
      {port_speed_path, SR_OP_CREATED, "openconfig-if-ethernet:SPEED_100GB"});

  EXPECT_TRUE(no_more_events());
}

// Tries to use an unsupported interface type, will fail in verify phase of the
// commit
TEST_F(TestGNMISysrepo, VerifyChangesFail) {
  const std::string iface_name("atm");

  gnmi::SetRequest req;
  GNMIPathBuilder pb(req.mutable_prefix());
  pb.append("interfaces").append("interface", {{"name", iface_name}})
      .append("config");
  {
    auto *update = req.add_update();
    GNMIPathBuilder pb(update->mutable_path());
    pb.append("name");
    update->mutable_val()->set_string_val(iface_name);
  }
  {
    auto *update = req.add_update();
    GNMIPathBuilder pb(update->mutable_path());
    pb.append("type");
    update->mutable_val()->set_string_val("iana-if-type:atm");
  }

  gnmi::SetResponse rep;
  ClientContext context;
  auto status = gnmi_stub->Set(&context, req, &rep);
  EXPECT_FALSE(status.ok());

  EXPECT_TRUE(no_more_events());
}

// GTest fixture for stream subscriptions (ON_CHANGE & SAMPLE)
// We use interfaces/interface/config/mtu as the subscription path.
class TestGNMISysrepoSubscribeStream : public TestGNMISysrepo {
 protected:
  using Clock = std::chrono::system_clock;

  TestGNMISysrepoSubscribeStream() { }

  using StreamType = grpc::ClientReaderWriter<
    gnmi::SubscribeRequest, gnmi::SubscribeResponse>;

  void SetUp() override {
    TestGNMISysrepo::SetUp();

    EXPECT_TRUE(create_iface(iface_name).ok());
    check_create_iface_events(iface_name);
    set_mtu(default_mtu, SR_OP_CREATED);

    stream = gnmi_stub->Subscribe(&context);
  }

  void TearDown() override {
    EXPECT_TRUE(stream->WritesDone());
    auto status = stream->Finish();
    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(no_more_events());
    clear_futures();

    TestGNMISysrepo::TearDown();
  }

  // For the sake of simplicity we use a synchronous gRPC client which means we
  // cannot give a deadline for the Read call. We therefore wrap the Read call
  // in a std::future object and use std::future::wait_for() to specify a
  // timeout. When the timeout expires the Read call is not cancelled. However,
  // as soon as the client calls WritesDone on the stream, Read will return
  // false and the future will complete.
  std::future<bool> &ReadFuture(StreamType *stream,
                                gnmi::SubscribeResponse *rep) {
    futures.emplace_back(std::async(
        std::launch::async, [stream, rep]{ return stream->Read(rep); }));
    return futures.back();
  }

  bool read_sync(StreamType *stream) {
    gnmi::SubscribeResponse rep;
    return stream->Read(&rep) && rep.sync_response();
  }

  // destroying the futures will not block if the client has called WritesDone
  void clear_futures() {
    futures.clear();
  }

  void set_mtu(unsigned int mtu, sr_change_oper_t oper = SR_OP_MODIFIED) {
    gnmi::SetRequest req;
    auto *update = req.add_update();
    GNMIPathBuilder pb(update->mutable_path());
    pb.append("interfaces").append("interface", {{"name", iface_name}})
        .append("config").append("mtu");
    update->mutable_val()->set_uint_val(mtu);

    gnmi::SetResponse rep;
    ClientContext context;
    auto status = gnmi_stub->Set(&context, req, &rep);
    EXPECT_TRUE(status.ok());
    std::string mtu_xpath("/openconfig-interfaces:interfaces/interface");
    mtu_xpath.append("[name='").append(iface_name).append("']/")
        .append("config/mtu");
    check_event({mtu_xpath, oper, std::to_string(mtu)});
  }

  void check_update(unsigned int mtu = default_mtu) {
    ASSERT_EQ(rep.response_case(), gnmi::SubscribeResponse::kUpdate);
    const auto &notification = rep.update();
    const auto &updates = notification.update();
    std::string expected_xpath("/openconfig-interfaces:interfaces/interface");
    expected_xpath.append("[name='").append(iface_name).append("']/")
        .append("config/mtu");
    for (const auto &update : updates) {
      auto xpath = gNMI_path_to_XPath(notification.prefix(), update.path());
      if (xpath == expected_xpath) {
        EXPECT_EQ(update.val().uint_val(), mtu);
        return;
      }
    }
  }

  static Clock::duration time_diff(const Clock::time_point &t1,
                                   const Clock::time_point &t2) {
    return (t1 > t2) ? (t1 - t2) : (t2 - t1);
  }

  using milliseconds = std::chrono::milliseconds;
  using nanoseconds = std::chrono::nanoseconds;

  static const unsigned int default_mtu{1500};

  const std::string iface_name{"eth0"};
  const milliseconds timeout{500};
  std::vector<std::future<bool> > futures;

  gnmi::SubscribeRequest req;
  gnmi::SubscriptionList *subList;
  gnmi::Subscription *sub;
  gnmi::SubscribeResponse rep;

  ClientContext context;
  std::unique_ptr<StreamType> stream;
};

class TestGNMISysrepoSubscribeStreamSample
    : public TestGNMISysrepoSubscribeStream {
 protected:
  TestGNMISysrepoSubscribeStreamSample() { }

  void SetUp() override {
    TestGNMISysrepoSubscribeStream::SetUp();

    subList = req.mutable_subscribe();
    subList->set_mode(gnmi::SubscriptionList::STREAM);
    sub = subList->add_subscription();
    GNMIPathBuilder pb(sub->mutable_path());
    pb.append("interfaces").append("interface", {{"name", iface_name}})
        .append("config").append("mtu");
    sub->set_mode(gnmi::SAMPLE);
    using std::chrono::duration_cast;
    sub->set_sample_interval(
        duration_cast<nanoseconds>(sample_interval).count());
  }

  const milliseconds sample_interval{200};
};

TEST_F(TestGNMISysrepoSubscribeStreamSample, Default) {
  EXPECT_TRUE(stream->Write(req));
  EXPECT_TRUE(stream->Read(&rep));
  check_update();
  EXPECT_TRUE(read_sync(stream.get()));

  auto start = Clock::now();
  const size_t num_samples = 3;
  for (size_t i = 0; i < num_samples; i++) {
    auto &f = ReadFuture(stream.get(), &rep);
    ASSERT_EQ(f.wait_for(timeout), std::future_status::ready);
    ASSERT_TRUE(f.get());
    auto now = Clock::now();
    auto expected = start + (i + 1) * sample_interval;
    EXPECT_LT(time_diff(now, expected), sample_interval / 2);
    check_update();
  }
}

TEST_F(TestGNMISysrepoSubscribeStreamSample, SuppressRedundant) {
  using std::chrono::duration_cast;
  sub->set_suppress_redundant(true);
  milliseconds heartbeat_interval(400);
  sub->set_heartbeat_interval(
      duration_cast<nanoseconds>(heartbeat_interval).count());

  EXPECT_TRUE(stream->Write(req));
  EXPECT_TRUE(stream->Read(&rep));
  check_update();
  EXPECT_TRUE(read_sync(stream.get()));

  auto start = Clock::now();
  {
    auto &f = ReadFuture(stream.get(), &rep);
    ASSERT_EQ(f.wait_for(timeout), std::future_status::ready);
    ASSERT_TRUE(f.get());
    auto now = Clock::now();
    auto expected = start + heartbeat_interval;
    EXPECT_LT(time_diff(now, expected), milliseconds(100));
    check_update();
  }

  {
    unsigned int new_mtu = 800;
    auto &f = ReadFuture(stream.get(), &rep);
    set_mtu(new_mtu);
    ASSERT_EQ(f.wait_for(timeout), std::future_status::ready);
    ASSERT_TRUE(f.get());
    auto now = Clock::now();
    auto expected = start + heartbeat_interval + sample_interval;
    EXPECT_LT(time_diff(now, expected), sample_interval / 2);
    check_update(new_mtu);
  }
}

TEST_F(TestGNMISysrepoSubscribeStreamSample, UpdatesOnly) {
  subList->set_updates_only(true);

  EXPECT_TRUE(stream->Write(req));
  // no update
  EXPECT_TRUE(read_sync(stream.get()));

  auto start = Clock::now();
  auto &f = ReadFuture(stream.get(), &rep);
  ASSERT_EQ(f.wait_for(timeout), std::future_status::ready);
  ASSERT_TRUE(f.get());
  auto now = Clock::now();
  auto expected = start + sample_interval;
  EXPECT_LT(time_diff(now, expected), sample_interval / 2);
  check_update();
}

class TestGNMISysrepoSubscribeStreamOnChange
    : public TestGNMISysrepoSubscribeStream {
 protected:
  TestGNMISysrepoSubscribeStreamOnChange() { }

  void SetUp() override {
    TestGNMISysrepoSubscribeStream::SetUp();

    subList = req.mutable_subscribe();
    subList->set_mode(gnmi::SubscriptionList::STREAM);
    sub = subList->add_subscription();
    GNMIPathBuilder pb(sub->mutable_path());
    pb.append("interfaces").append("interface", {{"name", iface_name}})
        .append("config").append("mtu");
    sub->set_mode(gnmi::ON_CHANGE);
  }

  const milliseconds refresh_interval{50};
};

TEST_F(TestGNMISysrepoSubscribeStreamOnChange, Default) {
  EXPECT_TRUE(stream->Write(req));
  EXPECT_TRUE(stream->Read(&rep));
  check_update();
  EXPECT_TRUE(read_sync(stream.get()));

  unsigned int mtu_1 = 800, mtu_2 = 1500;
  {
    auto start = Clock::now();
    auto &f = ReadFuture(stream.get(), &rep);
    ASSERT_EQ(f.wait_for(timeout), std::future_status::timeout);
    set_mtu(mtu_1);
    ASSERT_EQ(f.wait_for(timeout), std::future_status::ready);
    ASSERT_TRUE(f.get());
    auto now = Clock::now();
    auto expected = start + timeout;
    EXPECT_LT(time_diff(now, expected), 2 * refresh_interval);
    check_update(mtu_1);
  }
  {
    auto start = Clock::now();
    auto &f = ReadFuture(stream.get(), &rep);
    set_mtu(mtu_2);
    ASSERT_EQ(f.wait_for(timeout), std::future_status::ready);
    ASSERT_TRUE(f.get());
    auto now = Clock::now();
    auto expected = start;
    EXPECT_LT(time_diff(now, expected), 2 * refresh_interval);
    check_update(mtu_2);
  }
}

TEST_F(TestGNMISysrepoSubscribeStreamOnChange, UpdatesOnly) {
  subList->set_updates_only(true);
  EXPECT_TRUE(stream->Write(req));
  // no update
  EXPECT_TRUE(read_sync(stream.get()));
}

TEST_F(TestGNMISysrepoSubscribeStreamOnChange, Heartbeat) {
  using std::chrono::duration_cast;
  milliseconds heartbeat_interval(400);
  sub->set_heartbeat_interval(
      duration_cast<nanoseconds>(heartbeat_interval).count());

  EXPECT_TRUE(stream->Write(req));
  EXPECT_TRUE(stream->Read(&rep));
  check_update();
  EXPECT_TRUE(read_sync(stream.get()));

  auto start = Clock::now();
  auto &f = ReadFuture(stream.get(), &rep);
  ASSERT_EQ(f.wait_for(timeout), std::future_status::ready);
  ASSERT_TRUE(f.get());
  auto now = Clock::now();
  auto expected = start + heartbeat_interval;
  EXPECT_LT(time_diff(now, expected), 2 * refresh_interval);
  check_update();
}

#endif  // WITH_SYSREPO

}  // namespace
}  // namespace testing
}  // namespace proto
}  // namespace pi
