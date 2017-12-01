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

#include "gnmi_sysrepo.h"

#include <grpc++/grpc++.h>

#include <chrono>
#include <string>

extern "C" {

#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/xpath.h"

}

#include "gnmi/gnmi.grpc.pb.h"

using grpc::ServerContext;
using grpc::ServerReaderWriter;
using grpc::Status;
using grpc::StatusCode;

#define DEBUG

#ifdef DEBUG
#define ENABLE_SIMPLELOG true
#else
#define ENABLE_SIMPLELOG false
#endif

#define SIMPLELOG if (ENABLE_SIMPLELOG) std::cout

namespace pi {

namespace server {

namespace {

void convertToXPath(const gnmi::Path &path, std::string *path_str) {
  if (path.elem().size() == 0) return;
  for (const auto &elem : path.elem()) {
    // TODO(antonin): this is dubious and does not work for
    // interfaces/interface/.../state which is an example in the gNMI path
    // specification. It is unclear whether sysrepo supports such a path or if
    // extra work will be required to make it work.
    if (elem.name() == "...")
      path_str->append("/*");
    else
      path_str->append(elem.name());
    for (const auto &p : elem.key())
      path_str->append("[" + p.first + "='" + p.second + "']");
    path_str->append("/");
  }
  path_str->pop_back();  // remove trailing slash
}

void convertFromXPath(char *xpath, gnmi::Path *gpath) {
  sr_xpath_ctx_t ctx;
  char *node = xpath;
  char *xpath_ = xpath;
  while ((node = sr_xpath_next_node(xpath_, &ctx)) != NULL) {
    auto *pElem = gpath->add_elem();
    pElem->set_name(node);
    char *kn;
    auto *keys = pElem->mutable_key();
    while ((kn = sr_xpath_next_key_name(NULL, &ctx)) != NULL) {
      std::string kName(kn);  // needed here because sr_xpath_* mutates string
      auto *kv = sr_xpath_node_key_value(NULL, kn, &ctx);
      (*keys)[kName] = kv;
    }
    xpath_ = NULL;
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

void convertTypedValue(const sr_val_t *value, gnmi::TypedValue *typedV) {
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

}  // namespace

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
  (void) context; (void) request; (void) response;
  SIMPLELOG << "gNMI Set\n";
  SIMPLELOG << request->DebugString();
  return Status(StatusCode::UNIMPLEMENTED, "not implemented yet");
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
    auto tp = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
        tp.time_since_epoch()).count();
    notification->set_timestamp(timestamp);

    // TODO(antonin): keep connection open
    struct SysrepoSession {
      SysrepoSession() = default;

      ~SysrepoSession() {
        if (sess != NULL) sr_session_stop(sess);
        if (conn != NULL) sr_disconnect(conn);
      }

      bool open() {
        int rc = SR_ERR_OK;
        rc = sr_connect("gnmiServer", SR_CONN_DEFAULT, &conn);
        if (rc != SR_ERR_OK) return false;
        rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sess);
        if (rc != SR_ERR_OK) return false;
        return true;
      }

      sr_conn_ctx_t *conn{NULL};
      sr_session_ctx_t *sess{NULL};
    };

    SysrepoSession session;
    if (!session.open()) {
      return Status(StatusCode::UNKNOWN,
                    "Error when connection to yang datastore");
    }

    const auto &prefix = sub.prefix();
    for (const auto &subscription : sub.subscription()) {
      // TODO(antonin): This isn't part of the gNMI path but is required by
      // sysrepo so I need to find a way to infer this.
      std::string xpath("/openconfig-interfaces:");
      convertToXPath(prefix, &xpath);
      convertToXPath(subscription.path(), &xpath);
      SIMPLELOG << "ONCE subscription for XPath: " << xpath << "\n";

      sr_val_t *value = NULL;
      sr_val_iter_t *iter = NULL;
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
        convertTypedValue(value, update->mutable_val());
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
