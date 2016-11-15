#include "PI/pi.h"
#include "PI/int/pi_int.h"
#include "PI/frontends/proto/device_mgr.h"

#include <boost/functional/hash.hpp>

#include <memory>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <fstream>  // std::ifstream
#include <cstring>  // for std::memcmp

#include "p4info_to_and_from_proto.h"

#include "google/rpc/code.pb.h"

#include <gmock/gmock.h>

namespace {

using pi::fe::proto::DeviceMgr;
using device_id_t = uint64_t;
using Code = ::google::rpc::Code;

class DummyMatchKey {
  friend struct DummyMatchKeyHash;
 public:
  DummyMatchKey(const pi_match_key_t *match_key)
      : priority(match_key->priority),
        mk(&match_key->data[0], &match_key->data[match_key->data_size]) { }

  bool operator==(const DummyMatchKey& other) const {
    return priority == other.priority && mk == other.mk;
  }

  bool operator!=(const DummyMatchKey& other) const {
    return !(*this == other);
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

struct ActionData {
  ActionData(const pi_action_data_t *action_data)
      : data(&action_data->data[0],
             &action_data->data[action_data->data_size]) { }
  std::vector<char> data;
};

// TODO(antonin): support indirect, resources... as needed
class DummyTableEntry {
 public:
  DummyTableEntry(const pi_table_entry_t *table_entry)
      : ad(table_entry->entry.action_data) {
    assert(table_entry->entry_type == PI_ACTION_ENTRY_TYPE_DATA);
  }

 private:
  ActionData ad;
};

class DummyTable {
 public:
  pi_status_t entry_add(const pi_match_key_t *match_key,
                        const pi_table_entry_t *table_entry) {
    auto r = entries.emplace(DummyMatchKey(match_key),
                             DummyTableEntry(table_entry));
    // TODO(antonin): we need a better error code for duplicate entry
    return r.second ? PI_STATUS_SUCCESS : PI_STATUS_TARGET_ERROR;
  }

 private:
  std::unordered_map<DummyMatchKey, DummyTableEntry, DummyMatchKeyHash> entries;
};

class DummySwitch {
 public:
  DummySwitch(device_id_t device_id)
      : device_id(device_id) { }

  pi_status_t table_entry_add(pi_p4_id_t table_id,
                              const pi_match_key_t *match_key,
                              const pi_table_entry_t *table_entry) {
    // constructs DummyTable if not already in map
    return tables[table_id].entry_add(match_key, table_entry);
  }

 private:
  std::unordered_map<pi_p4_id_t, DummyTable> tables{};
  device_id_t device_id;
};

using ::testing::_;
using ::testing::Invoke;

class DummySwitchMock : public DummySwitch {
 public:
  DummySwitchMock(device_id_t device_id)
      : DummySwitch(device_id), sw(device_id) {
    // By default, all calls are delegated to the real object.
    ON_CALL(*this, table_entry_add(_,_,_))
        .WillByDefault(Invoke(&sw, &DummySwitch::table_entry_add));
  }
  MOCK_METHOD3(table_entry_add, pi_status_t(pi_p4_id_t, const pi_match_key_t *,
                                            const pi_table_entry_t *));
 private:
  DummySwitch sw;
};

// used to map device ids to DummySwitchMock instances; thread safe in case we
// want to make tests run in parallel in the future
class DeviceResolver {
 public:
  static device_id_t new_switch() {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    auto id = r->device_id++;
    r->map.emplace(
        id, std::unique_ptr<DummySwitchMock>(new DummySwitchMock(id)));
    return id;
  }

  static DummySwitchMock *get_switch(device_id_t device_id) {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    return r->map.at(device_id).get();
  }

  static void release_switch(device_id_t device_id) {
    auto r = DeviceResolver::get_instance();
    std::lock_guard<std::mutex> lock(r->m);
    r->map.erase(device_id);
  }

 private:
  static DeviceResolver *get_instance() {
    static DeviceResolver resolver;
    return &resolver;
  }

  mutable std::mutex m{};
  std::unordered_map<device_id_t, std::unique_ptr<DummySwitchMock> > map{};
  device_id_t device_id{0};
};

class DummySwitchWrapper {
 public:
  DummySwitchWrapper() {
    _device_id = DeviceResolver::new_switch();
    _sw = DeviceResolver::get_switch(_device_id);
  }

  device_id_t device_id() { return _device_id; }

  DummySwitchMock *sw() { return _sw; }

  ~DummySwitchWrapper() {
    DeviceResolver::release_switch(_device_id);
  }

 private:
  device_id_t _device_id{0};
  DummySwitchMock *_sw{nullptr};
};

}  // namespace

// here we implement the _pi_* methods which are needed for our tests
extern "C" {

pi_status_t _pi_init(void *) { return PI_STATUS_SUCCESS; }

pi_status_t _pi_destroy() { return PI_STATUS_SUCCESS; }

pi_status_t _pi_assign_device(pi_dev_id_t, const pi_p4info_t *,
                              pi_assign_extra_t *) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_remove_device(pi_dev_id_t) { return PI_STATUS_SUCCESS; }

pi_status_t _pi_session_init(pi_session_handle_t *) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_session_cleanup(pi_session_handle_t) {
  return PI_STATUS_SUCCESS;
}

pi_status_t _pi_table_entry_add(pi_session_handle_t session_handle,
                                pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                                const pi_match_key_t *match_key,
                                const pi_table_entry_t *table_entry,
                                int overwrite,
                                pi_entry_handle_t *entry_handle) {
  (void)session_handle;
  (void)overwrite;
  (void)entry_handle;
  return DeviceResolver::get_switch(dev_tgt.dev_id)->table_entry_add(
      table_id, match_key, table_entry);
}

// TODO(antonin)
// pi_status_t _pi_table_entries_fetch(pi_session_handle_t session_handle,
//                                     pi_dev_id_t dev_id, pi_p4_id_t table_id,
//                                     pi_table_fetch_res_t *res) {
//   (void)session_handle;
//   (void)dev_id;
//   (void)table_id;
//   (void)res;
//   return PI_STATUS_SUCCESS;
// }

// pi_status_t _pi_table_entries_fetch_done(pi_session_handle_t session_handle,
//                                          pi_table_fetch_res_t *res) {
//   (void)session_handle;
//   (void)res;
//   return PI_STATUS_SUCCESS;
// }

}

// Google Test fixture for Protobuf Frontend tests
class PIProtoFrontendTest : public ::testing::Test {
 protected:
  PIProtoFrontendTest()
      : mock(wrapper.sw()), device_id(wrapper.device_id()), mgr(device_id) { }

  static void SetUpTestCase() {
    DeviceMgr::init(256);
    pi_add_config_from_file(input_path, PI_CONFIG_TYPE_BMV2_JSON, &p4info);
    p4info_proto = pi::p4info::p4info_serialize_to_proto(p4info);
  }

  static void TearDownTestCase() {
    pi_destroy_config(p4info);
    DeviceMgr::destroy();
  }

  void SetUp() override {
    p4::tmp::DeviceAssignRequest_Extras extras;
    mgr.init(p4info_proto, extras);
  }

  void TearDown() override { }

  DeviceMgr::Status generic_add(pi_p4_id_t t_id, const p4::FieldMatch &mf,
                                const std::string &param_v);
  DeviceMgr::Status ExactOne_add(const std::string &mf_v,
                                 const std::string &param_v);
  DeviceMgr::Status LpmOne_add(const std::string &mf_v, unsigned int pLen,
                               const std::string &param_v);
  DeviceMgr::Status TernaryOne_add(const std::string &mf_v,
                                   const std::string &mask_v,
                                   const std::string &param_v);

  static constexpr const char *input_path = TESTDATADIR "/" "unittest.json";
  static pi_p4info_t *p4info;
  static p4::config::P4Info p4info_proto;

  DummySwitchWrapper wrapper{};
  DummySwitchMock *mock;
  device_id_t device_id;
  DeviceMgr mgr;
};

pi_p4info_t *PIProtoFrontendTest::p4info = nullptr;
p4::config::P4Info PIProtoFrontendTest::p4info_proto;

DeviceMgr::Status
PIProtoFrontendTest::generic_add(pi_p4_id_t t_id, const p4::FieldMatch &mf,
                                 const std::string &param_v) {
  p4::TableUpdate update;
  update.set_type(p4::TableUpdate_Type_INSERT);
  auto table_entry = update.mutable_table_entry();
  table_entry->set_table_id(t_id);
  auto mf_ptr = table_entry->add_match();
  *mf_ptr = mf;
  auto entry = table_entry->mutable_action();
  auto action = entry->mutable_action();
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  action->set_action_id(a_id);
  auto param = action->add_params();
  param->set_param_id(
      pi_p4info_action_param_id_from_name(p4info, a_id, "param"));
  param->set_value(param_v);
  return mgr.table_write(update);
}

DeviceMgr::Status
PIProtoFrontendTest::ExactOne_add(const std::string &mf_v,
                                  const std::string &param_v) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "ExactOne");
  p4::FieldMatch mf;
  mf.set_field_id(pi_p4info_field_id_from_name(p4info, "header_test.field32"));
  auto mf_exact = mf.mutable_exact();
  mf_exact->set_value(mf_v);
  return generic_add(t_id, mf, param_v);
}

DeviceMgr::Status
PIProtoFrontendTest::LpmOne_add(const std::string &mf_v, unsigned int pLen,
                                const std::string &param_v) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "LpmOne");
  p4::FieldMatch mf;
  mf.set_field_id(pi_p4info_field_id_from_name(p4info, "header_test.field32"));
  auto mf_lpm = mf.mutable_lpm();
  mf_lpm->set_value(mf_v);
  mf_lpm->set_prefix_len(pLen);
  return generic_add(t_id, mf, param_v);
}

DeviceMgr::Status
PIProtoFrontendTest::TernaryOne_add(const std::string &mf_v,
                                    const std::string &mask_v,
                                    const std::string &param_v) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "TernaryOne");
  p4::FieldMatch mf;
  mf.set_field_id(pi_p4info_field_id_from_name(p4info, "header_test.field32"));
  auto mf_lpm = mf.mutable_ternary();
  mf_lpm->set_value(mf_v);
  mf_lpm->set_mask(mask_v);
  return generic_add(t_id, mf, param_v);
}

namespace {

// started out using a lambda in the test cases, but it was too much duplicated
// code
// TODO(antonin): build a matcher using googlemock base matchers (e.g. Field...)
// instead?
struct MatchKeyMatcher {
 public:
  MatchKeyMatcher(pi_p4_id_t t_id, const std::string &v)
      : t_id(t_id), v(v) { }

  bool operator()(const pi_match_key_t *mk) const {
    return (mk->table_id == t_id
            && mk->data_size == v.size()
            && !std::memcmp(mk->data, v.data(), v.size()));
  }

 private:
  pi_p4_id_t t_id;
  std::string v;
};

// TODO(antonin): indirect, resources, ...
struct TableEntryMatcher_Direct {
 public:
  TableEntryMatcher_Direct(pi_p4_id_t a_id, const std::string &v)
      : a_id(a_id), v(v) { }

  bool operator()(const pi_table_entry_t *t_entry) const {
    if (t_entry->entry_type != PI_ACTION_ENTRY_TYPE_DATA) return false;
    const auto action_data = t_entry->entry.action_data;
    return (action_data->action_id == a_id
            && action_data->data_size == v.size()
            && !std::memcmp(action_data->data, v.data(), v.size()));
  }

 private:
  pi_p4_id_t a_id;
  std::string v;
};

}  // namespace

using ::testing::Truly;

// TODO(antonin): maybe use value-parametrized tests to avoid code duplication,
// except if we are going to have some tests dependent on the match type

TEST_F(PIProtoFrontendTest, AddExact) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "ExactOne");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  // TODO(antonin): check for error if size not right
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string adata(6, '\x00');
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mf));
  auto ad_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, ad_matcher))
      .Times(2);
  DeviceMgr::Status status;
  status = ExactOne_add(mf, adata);
  ASSERT_EQ(status.code(), Code::OK);
  // second is error because duplicate match key
  status = ExactOne_add(mf, adata);
  ASSERT_NE(status.code(), Code::OK);
}

TEST_F(PIProtoFrontendTest, AddLpm) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "LpmOne");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  // TODO(antonin): check for error if size not right
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  // adding the pref length (12) in little endian format, over 4 bytes
  std::string mk = mf + std::string("\x0c\x00\x00\x00", 4);
  std::string adata(6, '\x00');
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mk));
  auto ad_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, ad_matcher))
      .Times(2);
  DeviceMgr::Status status;
  status = LpmOne_add(mf, 12, adata);
  ASSERT_EQ(status.code(), Code::OK);
  // second is error because duplicate match key
  status = LpmOne_add(mf, 12, adata);
  ASSERT_NE(status.code(), Code::OK);
}

TEST_F(PIProtoFrontendTest, AddTernary) {
  auto t_id = pi_p4info_table_id_from_name(p4info, "TernaryOne");
  auto a_id = pi_p4info_action_id_from_name(p4info, "actionA");
  // TODO(antonin): check for error if size not right
  std::string mf("\xaa\xbb\xcc\xdd", 4);
  std::string mask("\xff\x01\xf0\x0f", 4);
  // adding the mask
  std::string mk = mf + mask;
  std::string adata(6, '\x00');
  auto mk_matcher = Truly(MatchKeyMatcher(t_id, mk));
  auto ad_matcher = Truly(TableEntryMatcher_Direct(a_id, adata));
  EXPECT_CALL(*mock, table_entry_add(t_id, mk_matcher, ad_matcher))
      .Times(2);
  DeviceMgr::Status status;
  status = TernaryOne_add(mf, mask, adata);
  ASSERT_EQ(status.code(), Code::OK);
  // second is error because duplicate match key
  status = TernaryOne_add(mf, mask, adata);
  ASSERT_NE(status.code(), Code::OK);
}
