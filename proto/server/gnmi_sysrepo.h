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

#ifndef PROTO_SERVER_GNMI_SYSREPO_H_
#define PROTO_SERVER_GNMI_SYSREPO_H_

#include <grpc++/grpc++.h>

#include <string>

#include "gnmi/gnmi.grpc.pb.h"

namespace pi {

namespace server {

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
};

}  // namespace server

}  // namespace pi

#endif  // PROTO_SERVER_GNMI_SYSREPO_H_
