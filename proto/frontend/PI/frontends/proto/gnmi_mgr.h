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

#ifndef PI_FRONTENDS_PROTO_GNMI_MGR_H_
#define PI_FRONTENDS_PROTO_GNMI_MGR_H_

#include <memory>

#include "gnmi/gnmi.pb.h"
#include "google/rpc/status.pb.h"

namespace pi {

namespace fe {

namespace proto {

// forward declaration for PIMPL class
class GnmiMgrImp;

class GnmiMgr {
 public:
  using Status = ::google::rpc::Status;

  GnmiMgr();
  ~GnmiMgr();

  Status get(const gnmi::GetRequest &request,
             gnmi::GetResponse *response) const;

  Status set(const gnmi::SetRequest &request,
             gnmi::SetResponse *response);

 private:
  // PIMPL design
  std::unique_ptr<GnmiMgrImp> pimp;
};

}  // namespace proto

}  // namespace fe

}  // namespace pi

#endif  // PI_FRONTENDS_PROTO_GNMI_MGR_H_
