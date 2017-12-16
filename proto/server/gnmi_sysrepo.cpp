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

#include "gnmi.h"

extern "C" {

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <sysrepo/values.h>
#include <sysrepo/xpath.h>

}

#include <grpc++/grpc++.h>

#include <chrono>
#include <cmath>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "gnmi/gnmi.grpc.pb.h"
#include "log.h"

using grpc::ServerContext;
using grpc::ServerReaderWriter;
using grpc::Status;
using grpc::StatusCode;

namespace pi {

namespace server {

namespace {

void convertFromXPath(char *xpath, gnmi::Path *gpath) {
  sr_xpath_ctx_t ctx;
  char *node = xpath;
  char *xpath_ = xpath;
  while ((node = sr_xpath_next_node(xpath_, &ctx)) != nullptr) {
    auto *pElem = gpath->add_elem();
    pElem->set_name(node);
    char *kn;
    auto *keys = pElem->mutable_key();
    while ((kn = sr_xpath_next_key_name(nullptr, &ctx)) != nullptr) {
      std::string kName(kn);  // needed here because sr_xpath_* mutates string
      auto *kv = sr_xpath_node_key_value(nullptr, kn, &ctx);
      (*keys)[kName] = kv;
    }
    xpath_ = nullptr;
  }
}

bool isLeaf(const sr_val_t *value) {
  switch (value->type) {
    case SR_UNKNOWN_T:
      assert(0);
      return false;
    case SR_TREE_ITERATOR_T:
      assert(0);
      return false;
    case SR_LIST_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LEAF_EMPTY_T:
    case SR_INSTANCEID_T:
      return false;
    case SR_BITS_T:   // TODO(antonin): what should this map to?
      return false;
    default:
      return true;
  }
  return true;
}

void convertToTypedValue(const sr_val_t *value, gnmi::TypedValue *typedV) {
  switch (value->type) {
    case SR_BINARY_T:
      typedV->set_bytes_val(value->data.binary_val);
      break;
    case SR_BITS_T:
      break;
    case SR_BOOL_T:
      typedV->set_bool_val(value->data.bool_val);
      break;
    case SR_DECIMAL64_T:
      typedV->set_float_val(value->data.decimal64_val);
      break;
    case SR_ENUM_T:
      typedV->set_string_val(value->data.enum_val);
      break;
    case SR_INT8_T:
      typedV->set_int_val(value->data.int8_val);
      break;
    case SR_INT16_T:
      typedV->set_int_val(value->data.int16_val);
      break;
    case SR_INT32_T:
      typedV->set_int_val(value->data.int32_val);
      break;
    case SR_INT64_T:
      typedV->set_int_val(value->data.int64_val);
      break;
    case SR_STRING_T:
      typedV->set_string_val(value->data.string_val);
      break;
    case SR_UINT8_T:
      typedV->set_uint_val(value->data.uint8_val);
      break;
    case SR_UINT16_T:
      typedV->set_uint_val(value->data.uint16_val);
      break;
    case SR_UINT32_T:
      typedV->set_uint_val(value->data.uint32_val);
      break;
    case SR_UINT64_T:
      typedV->set_uint_val(value->data.uint64_val);
      break;
    case SR_ANYXML_T:
      typedV->set_ascii_val(value->data.anyxml_val);
      break;
    case SR_ANYDATA_T:
      typedV->set_ascii_val(value->data.anydata_val);
      break;
    case SR_IDENTITYREF_T:
      typedV->set_string_val(value->data.string_val);
      break;
    default:  // cannot happen because of previous switch
      assert(0);
      break;
  }
}

std::string convertDecimal64ToStr(const gnmi::Decimal64 &dec64) {
  auto pow10 = [](uint32_t n) {
    int64_t v = 1;
    while (n) {
      if (n & 1) {
        v *= 10;
        n--;
      } else {
        v = v * v;
        n >>= 1;
      }
    }
    return v;
  };
  int64_t multiplier = pow10(dec64.precision());
  int64_t before_dec = dec64.digits() / multiplier;
  int64_t after_dec = std::abs(dec64.digits() - (before_dec * multiplier));
  auto after_dec_str = std::to_string(after_dec);
  uint32_t zero_padding = dec64.precision() - after_dec_str.size();
  return std::to_string(before_dec) + "." + std::string(zero_padding, '0')
      + after_dec_str;
}

bool isTypedValueScalar(const gnmi::TypedValue &typedV) {
  switch (typedV.value_case()) {
    case gnmi::TypedValue::kStringVal:
    case gnmi::TypedValue::kIntVal:
    case gnmi::TypedValue::kUintVal:
    case gnmi::TypedValue::kBoolVal:
    case gnmi::TypedValue::kBytesVal:
    case gnmi::TypedValue::kFloatVal:
    case gnmi::TypedValue::kDecimalVal:
      return true;
    case gnmi::TypedValue::kLeaflistVal:
      return false;
    default:
      return false;
  }
}

bool isTypedValueLeaf(const gnmi::TypedValue &typedV) {
  return isTypedValueScalar(typedV) ||
      typedV.value_case() == gnmi::TypedValue::kLeaflistVal;
}

std::string convertLeafTypedValueToStr(const gnmi::TypedValue &typedV) {
  switch (typedV.value_case()) {
    case gnmi::TypedValue::kStringVal:
      return typedV.string_val();
    case gnmi::TypedValue::kIntVal:
      return std::to_string(typedV.int_val());
    case gnmi::TypedValue::kUintVal:
      return std::to_string(typedV.uint_val());
    case gnmi::TypedValue::kBoolVal:
      return typedV.bool_val() ? "true" : "false";
    case gnmi::TypedValue::kBytesVal:
      return typedV.bytes_val();
    case gnmi::TypedValue::kFloatVal:
      return std::to_string(typedV.float_val());
    case gnmi::TypedValue::kDecimalVal:
      return convertDecimal64ToStr(typedV.decimal_val());
    default:
      return "";
  }
}

// opens a session to sysrepo and keep it open until the object is destroyed
struct SysrepoSession {
  SysrepoSession() = default;

  ~SysrepoSession() {
    if (sess != nullptr) sr_session_stop(sess);
    if (conn != nullptr) sr_disconnect(conn);
  }

  bool open() {
    int rc = SR_ERR_OK;
    rc = sr_connect("gnmiServer", SR_CONN_DEFAULT, &conn);
    if (rc != SR_ERR_OK) return false;
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sess);
    if (rc != SR_ERR_OK) return false;
    return true;
  }

  sr_conn_ctx_t *conn{nullptr};
  sr_session_ctx_t *sess{nullptr};
};

// checks if str starts with substr
bool starts_with(const std::string &str, const std::string &substr) {
  return str.substr(0, substr.size()) == substr;
}

// This class lists all the openconfig modules installed in sysrepo and loads
// them into a libyang context. This is useful for mapping a gNMI path to the
// corresponding module. This may be useful in the future for other things.
class LYContext {
 public:
  using Map = std::unordered_map<std::string, const struct lys_module *>;
  using iterator = Map::iterator;
  using const_iterator = Map::const_iterator;

  LYContext() {
    parse_schemas();
  }

  const struct lys_module *get_module(const std::string &origin) const {
    auto it = modules.find(origin);
    return (it == modules.end()) ? nullptr : it->second;
  }

  ~LYContext() {
    if (ctx != nullptr) {
      ly_ctx_clean(ctx, nullptr);
      ly_ctx_destroy(ctx, nullptr);
    }
  }

  iterator begin() { return modules.begin(); }
  const_iterator begin() const { return modules.begin(); }
  iterator end() { return modules.end(); }
  const_iterator end() const { return modules.end(); }

 private:
  void parse_schemas() {
    SysrepoSession session;
    if (!session.open()) return;
    sr_schema_t *schemas = nullptr;
    size_t schema_cnt = 0;
    struct ly_ctx *ctx = ly_ctx_new(nullptr, 0);
    int rc = 0;
    rc = sr_list_schemas(session.sess, &schemas, &schema_cnt);
    if (rc != SR_ERR_OK) return;

    auto dirname = [](const std::string &path) {
      auto sep_pos = path.find_last_of('/');
      if (sep_pos == std::string::npos) return path;
      return path.substr(0, sep_pos);
    };

    for (size_t i = 0; i < schema_cnt; i++) {
      if (!schemas[i].installed) continue;
      const char *module_name = schemas[i].module_name;
      // Avoid issues if different modules with colliding paths are installed.
      // For example, if both openconfig-interfaces and ietf-interfaces are
      // installed. Since we only support modules in the openconfig tree for
      // now, this check makes sense.
      // See https://github.com/sysrepo/sysrepo/issues/1015
      if (!starts_with(module_name, "openconfig")) continue;
      const char *path_yang = schemas[i].revision.file_path_yang;
      if (ly_ctx_set_searchdir(ctx, dirname(path_yang).c_str()) != EXIT_SUCCESS)
        continue;
      const struct lys_module *module = lys_parse_path(
          ctx, path_yang, LYS_IN_YANG);
      if (module == nullptr) continue;
      modules.emplace(module_name, module);
    }

    sr_free_schemas(schemas, schema_cnt);
  }

  struct ly_ctx *ctx{nullptr};
  std::unordered_map<std::string, const struct lys_module *> modules{};
};

// Utility class to convert gNMI paths to XPaths that sysrepo can understand
// The difficulty is that gNMI does not assume that the module name is included
// in the path, as long as there is no ambiguity, i.e. no overlap in the
// implemented schemas. However, sysrepo does require the module name as a
// namespace qualifier for the first element in the path. To retrieve the module
// name, we iterate over all the schemas explicitly installed (aka implemented)
// in sysrepo and look at the root node(s) for each one. We then associate that
// root node name to the corresponding schema name, which lets us do the
// conversion from gNMI path to sysrepo XPath.
class XPathBuilder {
 public:
  explicit XPathBuilder(LYContext *LY_ctx)
      : LY_ctx(LY_ctx) {
    scan_schemas();
  }

  void appendToXPath(const gnmi::Path &path, std::string *path_str) {
    if (path.elem().size() == 0) return;
    for (const auto &elem : path.elem()) {
      path_str->append("/");
      // TODO(antonin): this is dubious and does not work for
      // interfaces/interface/.../state which is an example in the gNMI path
      // specification. It is unclear whether sysrepo supports such a path or if
      // extra work will be required to make it work.
      if (elem.name() == "...")
        path_str->append("/*");
      else
        path_str->append(elem.name());
      for (const auto &p : elem.key()) {
        // if value is wildcard, do not include the key at all
        if (p.second != "*")
          path_str->append("[" + p.first + "='" + p.second + "']");
      }
    }
  }

  // returns true on success
  bool setXPathOrigin(std::string *path_str, const std::string &origin = "") {
    if (path_str->empty() || path_str->at(0) != '/') return false;
    auto node_sep = path_str->find_first_of('/', 1);
    std::string first_node;
    std::string remaining_path;
    if (node_sep == std::string::npos) {
      first_node = path_str->substr(1);
    } else {
      first_node = path_str->substr(1, node_sep - 1);
      remaining_path = path_str->substr(node_sep);
    }
    auto ns_sep = first_node.find_first_of(':');
    if (ns_sep == std::string::npos) {
      if (origin.empty()) {
        auto inferred_origin_it = namespace_mapping.find(first_node);
        if (inferred_origin_it == namespace_mapping.end()) return false;
        first_node = inferred_origin_it->second + ":" + first_node;
      } else {
        first_node = origin + ":" + first_node;
      }
      *path_str = "/" + first_node + remaining_path;
    }
    return true;
  }

 private:
  // TODO(antonin): handle errors in scan_schemas
  void scan_schemas() {
    // iterate over supported modules
    for (const auto &p : *LY_ctx) {
      const auto &module_name = p.first;
      const auto *module = p.second;
      const struct lys_node *node = nullptr;
      while ((node = lys_getnext(node, nullptr, module, 0)) != nullptr) {
        auto ns_it = namespace_mapping.find(node->name);
        if (ns_it == namespace_mapping.end()) {
          namespace_mapping.emplace(node->name, module_name);
          SIMPLELOG << "Path '" << node->name << "' is in module "
                    << module_name << "\n";
        } else {
          SIMPLELOG << "Path '" << node->name << " 'is in multiple modules\n";
        }
      }
    }
  }

  LYContext *LY_ctx;
  std::unordered_map<std::string, std::string> namespace_mapping{};
};

std::string extractOrigin(const std::string &path) {
  if (path.empty()) return "";
  auto start_pos = (path[0] == '/') ? 1 : 0;
  auto end_pos = path.find_first_of(':');
  return (end_pos == std::string::npos) ?
      path.substr(start_pos) : path.substr(start_pos, end_pos - start_pos);
}

sr_type_t convert_LY_type_to_sysrepo_type(LY_DATA_TYPE LY_type) {
  switch (LY_type) {
    case LY_TYPE_ERR:
      return SR_UNKNOWN_T;
    case LY_TYPE_DER:
      return SR_UNKNOWN_T;
    case LY_TYPE_BINARY:
      return SR_BINARY_T;
    case LY_TYPE_BITS:
      return SR_BITS_T;
    case LY_TYPE_BOOL:
      return SR_BOOL_T;
    case LY_TYPE_DEC64:
      return SR_DECIMAL64_T;
    case LY_TYPE_EMPTY:
      return SR_LEAF_EMPTY_T;
    case LY_TYPE_ENUM:
      return SR_ENUM_T;
    case LY_TYPE_IDENT:
      return SR_IDENTITYREF_T;
    case LY_TYPE_INST:
      return SR_INSTANCEID_T;
    case LY_TYPE_LEAFREF:
      return SR_UNKNOWN_T;
    case LY_TYPE_STRING:
      return SR_STRING_T;
    case LY_TYPE_UNION:
      return SR_UNKNOWN_T;
    case LY_TYPE_INT8:
      return SR_INT8_T;
    case LY_TYPE_UINT8:
      return SR_UINT8_T;
    case LY_TYPE_INT16:
      return SR_INT16_T;
    case LY_TYPE_UINT16:
      return SR_UINT16_T;
    case LY_TYPE_INT32:
      return SR_INT32_T;
    case LY_TYPE_UINT32:
      return SR_UINT32_T;
    case LY_TYPE_INT64:
      return SR_INT64_T;
    case LY_TYPE_UINT64:
      return SR_UINT64_T;
    default:
      return SR_UNKNOWN_T;
  }
  return SR_UNKNOWN_T;
}

// This class was meant to be used to resolve the type of a node in the schema
// tree. Because sysrepo offers a set_item_str function, it seems that this
// class is in fact not needed.
// TODO(antonin): remove
class LeafTypeCache {
 public:
  explicit LeafTypeCache(LYContext *LY_ctx)
      : LY_ctx(LY_ctx) { }

  // returns {} if not a leaf
  // schema_path needs to include origin
  std::vector<sr_type_t> get_types(sr_session_ctx_t *session,
                                   const std::string &schema_path) const {
    auto origin = extractOrigin(schema_path);
    if (origin == "") return {};
    const auto *module = LY_ctx->get_module(origin);
    if (module == nullptr) return {};
    auto *LY_set = lys_find_path(module, nullptr, schema_path.c_str());
    if (LY_set == nullptr) return {};
    // TODO(antonin): when can we have more than one node in the set?
    if (LY_set->number != 1) return {};
    auto LY_node = LY_set->set.s[0];
    if (LY_node->nodetype != LYS_LEAF) {
      SIMPLELOG << "Schema path " << schema_path << " is not a leaf\n";
      return {};
    }
    auto *LY_leaf = reinterpret_cast<struct lys_node_leaf *>(LY_node);
    std::vector<sr_type_t> types;
    get_node_types(&LY_leaf->type, &types);
    return types;
  }

 private:
  void get_node_types(const struct lys_type *LY_type,
                      std::vector<sr_type_t> *types) const {
    if (LY_type->base == LY_TYPE_LEAFREF) {
      const auto *LY_lref = &LY_type->info.lref;
      const auto *LY_leaf = LY_lref->target;
      assert(LY_leaf->nodetype == LYS_LEAF);
      return get_node_types(&LY_leaf->type, types);
    } else if (LY_type->base == LY_TYPE_UNION) {
      const auto *LY_union = &LY_type->info.uni;
      for (unsigned int i = 0; i < LY_union->count; i++)
        get_node_types(&LY_union->types[i], types);
    } else {
      types->push_back(convert_LY_type_to_sysrepo_type(LY_type->base));
    }
  }

  LYContext *LY_ctx;
};

}  // namespace

class gNMIServiceSysrepoImpl : public gnmi::gNMI::Service {
 private:
  grpc::Status Capabilities(grpc::ServerContext *context,
                            const gnmi::CapabilityRequest *request,
                            gnmi::CapabilityResponse *response) override;

  grpc::Status Get(grpc::ServerContext *context,
                   const gnmi::GetRequest *request,
                   gnmi::GetResponse *response) override;

  grpc::Status Set(grpc::ServerContext *context,
                   const gnmi::SetRequest *request,
                   gnmi::SetResponse *response) override;

  grpc::Status Subscribe(
      grpc::ServerContext *context,
      grpc::ServerReaderWriter<gnmi::SubscribeResponse,
                               gnmi::SubscribeRequest> *stream) override;

  int64_t get_timestamp() const {
    auto tp = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
        tp.time_since_epoch()).count();
    return timestamp;
  }

  LYContext LY_ctx;
  XPathBuilder xpath_builder{&LY_ctx};
  LeafTypeCache leaf_type_cache{&LY_ctx};
};

std::unique_ptr<gnmi::gNMI::Service> make_gnmi_service_sysrepo() {
  return std::unique_ptr<gnmi::gNMI::Service>(new gNMIServiceSysrepoImpl());
}

Status
gNMIServiceSysrepoImpl::Capabilities(ServerContext *context,
                                     const gnmi::CapabilityRequest *request,
                                     gnmi::CapabilityResponse *response) {
  (void) context; (void) request; (void) response;
  SIMPLELOG << "gNMI Capabilities\n";
  SIMPLELOG << request->DebugString();
  return Status(StatusCode::UNIMPLEMENTED, "not implemented yet");
}

Status
gNMIServiceSysrepoImpl::Get(ServerContext *context,
                            const gnmi::GetRequest *request,
                            gnmi::GetResponse *response) {
  (void) context; (void) request; (void) response;
  SIMPLELOG << "gNMI Get\n";
  SIMPLELOG << request->DebugString();
  return Status(StatusCode::UNIMPLEMENTED, "not implemented yet");
}

Status
gNMIServiceSysrepoImpl::Set(ServerContext *context,
                            const gnmi::SetRequest *request,
                            gnmi::SetResponse *response) {
  (void) context;
  SIMPLELOG << "gNMI Set\n";
  SIMPLELOG << request->DebugString();
  int rc = SR_ERR_OK;
  const auto &prefix = request->prefix();

  if (!request->replace().empty())
    return Status(StatusCode::UNIMPLEMENTED, "'replace' not implemented yet");

  SysrepoSession session;
  if (!session.open()) {
    return Status(StatusCode::UNKNOWN,
                  "Error when connecting to yang datastore");
  }

  auto make_xpath = [this, &prefix](const gnmi::Path &path,
                                    std::string *xpath) {
    xpath_builder.appendToXPath(prefix, xpath);
    xpath_builder.appendToXPath(path, xpath);
    if (!xpath_builder.setXPathOrigin(xpath, path.origin())) return false;
    return true;
  };

  for (const auto &path : request->delete_()) {
    std::string xpath;
    if (!make_xpath(path, &xpath)) {
      return Status(StatusCode::INVALID_ARGUMENT,
                    "Cannot convert gNMI path to XPath");
    }
    rc = sr_delete_item(session.sess, xpath.c_str(), SR_EDIT_DEFAULT);
    if (rc != SR_ERR_OK)
      return Status(StatusCode::UNKNOWN, "Error when deleting item");
  }

  for (const auto &update : request->update()) {
    const auto &path = update.path();
    std::string xpath;
    if (!make_xpath(path, &xpath)) {
      return Status(StatusCode::INVALID_ARGUMENT,
                    "Cannot convert gNMI path to XPath");
    }
    const auto &typedV = update.val();
    if (!isTypedValueLeaf(typedV)) {
      return Status(StatusCode::UNIMPLEMENTED,
                    "We only support setting leaves for now");
    }
    if (typedV.value_case() == gnmi::TypedValue::kLeaflistVal) {
      for (const auto &typedV_e : typedV.leaflist_val().element()) {
        if (!isTypedValueScalar(typedV_e)) {
          return Status(StatusCode::INVALID_ARGUMENT,
                        "Leaflist entry must be a scalar");
        }
        auto value_str = convertLeafTypedValueToStr(typedV_e);
        rc = sr_set_item_str(session.sess, xpath.c_str(), value_str.c_str(),
                             SR_EDIT_DEFAULT);
        if (rc != SR_ERR_OK)
          return Status(StatusCode::UNKNOWN,
                        "Error when setting leaf list element");
      }
    } else {
      auto value_str = convertLeafTypedValueToStr(typedV);
      rc = sr_set_item_str(session.sess, xpath.c_str(), value_str.c_str(),
                           SR_EDIT_DEFAULT);
      if (rc != SR_ERR_OK)
        return Status(StatusCode::UNKNOWN, "Error when setting item");
    }
  }

  rc = sr_commit(session.sess);
  if (rc != SR_ERR_OK) {
    return Status(StatusCode::UNKNOWN, "Error when comitting changes");
    // TODO(antonin): call sr_get_last_errors
  }

  // TODO(antonin): other response fields
  response->set_timestamp(get_timestamp());

  return Status::OK;
}

Status
gNMIServiceSysrepoImpl::Subscribe(
    ServerContext *context,
    ServerReaderWriter<gnmi::SubscribeResponse,
                       gnmi::SubscribeRequest> *stream) {
  SIMPLELOG << "gNMI Subscribe\n";
  gnmi::SubscribeRequest request;
  while (stream->Read(&request)) {
    if (!request.has_subscribe()) {
      return Status(StatusCode::UNIMPLEMENTED,
                    "Only subscription lists supported for now");
    }
    const auto &sub = request.subscribe();
    if (sub.mode() != gnmi::SubscriptionList::ONCE) {
      return Status(StatusCode::UNIMPLEMENTED,
                    "Only subscriptions with ONCE mode supported for now");
    }

    gnmi::SubscribeResponse response;
    auto *notification = response.mutable_update();
    notification->set_timestamp(get_timestamp());

    // TODO(antonin): keep connection open
    SysrepoSession session;
    if (!session.open()) {
      return Status(StatusCode::UNKNOWN,
                    "Error when connecting to yang datastore");
    }

    const auto &prefix = sub.prefix();
    for (const auto &subscription : sub.subscription()) {
      std::string xpath;
      xpath_builder.appendToXPath(prefix, &xpath);
      xpath_builder.appendToXPath(subscription.path(), &xpath);
      if (!xpath_builder.setXPathOrigin(&xpath, subscription.path().origin())) {
        return Status(StatusCode::INVALID_ARGUMENT,
                      "Cannot convert gNMI path to XPath");
      }
      SIMPLELOG << "ONCE subscription for XPath: " << xpath << "\n";

      sr_val_t *value = nullptr;
      sr_val_iter_t *iter = nullptr;
      int rc = SR_ERR_OK;

      // get all list instances with their content (recursive)
      rc = sr_get_items_iter(session.sess, xpath.c_str(), &iter);
      if (rc != SR_ERR_OK) {
        return Status(StatusCode::UNKNOWN,
                      "Error while retrieving subscription items");
      }

      while (sr_get_item_next(session.sess, iter, &value) == SR_ERR_OK) {
        char *update_xpath = value->xpath;
        if (!isLeaf(value)) {
          sr_free_val(value);
          continue;
        }
        if (value->dflt) {  // unset
          sr_free_val(value);
          continue;
        }

        SIMPLELOG << "Update XPath: " << update_xpath << "\n";
        // sr_print_val(value);

        auto update = notification->add_update();
        // TODO(antonin): use prefix for smaller messages
        // TODO(antonin): investigate aggregation
        convertFromXPath(update_xpath, update->mutable_path());
        convertToTypedValue(value, update->mutable_val());
        sr_free_val(value);
      }
      sr_free_val_iter(iter);
    }
    // response.PrintDebugString();
    stream->Write(response);
    // Following the transmission of all updates which correspond to data items
    // within the set of paths specified within the subscription list, a
    // SubscribeResponse message with the sync_response field set to true MUST
    // be transmitted, and the channel over which the SubscribeRequest was
    // received MUST be closed.
    gnmi::SubscribeResponse EOM;
    EOM.set_sync_response(true);
    stream->Write(EOM);
    break;
  }
  return Status::OK;
}

}  // namespace server

}  // namespace pi
