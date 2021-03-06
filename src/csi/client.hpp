// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __CSI_CLIENT_HPP__
#define __CSI_CLIENT_HPP__

#include <csi/spec.hpp>

#include <process/grpc.hpp>

#include "csi/rpc.hpp"

namespace mesos {
namespace csi {
namespace v0 {

class Client
{
public:
  Client(const process::grpc::client::Connection& _connection,
         const process::grpc::client::Runtime& _runtime)
    : connection(_connection), runtime(_runtime) {}

  template <RPC rpc>
  process::Future<typename RPCTraits<rpc>::response_type> call(
      const typename RPCTraits<rpc>::request_type& request);

private:
  process::grpc::client::Connection connection;
  process::grpc::client::Runtime runtime;
};


template <>
process::Future<GetPluginInfoResponse>
Client::call<GET_PLUGIN_INFO>(
    const GetPluginInfoRequest& request);


template <>
process::Future<GetPluginCapabilitiesResponse>
Client::call<GET_PLUGIN_CAPABILITIES>(
    const GetPluginCapabilitiesRequest& request);


template <>
process::Future<ProbeResponse>
Client::call<PROBE>(
    const ProbeRequest& request);


template <>
process::Future<CreateVolumeResponse>
Client::call<CREATE_VOLUME>(
    const CreateVolumeRequest& request);


template <>
process::Future<DeleteVolumeResponse>
Client::call<DELETE_VOLUME>(
    const DeleteVolumeRequest& request);


template <>
process::Future<ControllerPublishVolumeResponse>
Client::call<CONTROLLER_PUBLISH_VOLUME>(
    const ControllerPublishVolumeRequest& request);


template <>
process::Future<ControllerUnpublishVolumeResponse>
Client::call<CONTROLLER_UNPUBLISH_VOLUME>(
    const ControllerUnpublishVolumeRequest& request);


template <>
process::Future<ValidateVolumeCapabilitiesResponse>
Client::call<VALIDATE_VOLUME_CAPABILITIES>(
    const ValidateVolumeCapabilitiesRequest& request);


template <>
process::Future<ListVolumesResponse>
Client::call<LIST_VOLUMES>(
    const ListVolumesRequest& request);


template <>
process::Future<GetCapacityResponse>
Client::call<GET_CAPACITY>(
    const GetCapacityRequest& request);


template <>
process::Future<ControllerGetCapabilitiesResponse>
Client::call<CONTROLLER_GET_CAPABILITIES>(
    const ControllerGetCapabilitiesRequest& request);


template <>
process::Future<NodeStageVolumeResponse>
Client::call<NODE_STAGE_VOLUME>(
    const NodeStageVolumeRequest& request);


template <>
process::Future<NodeUnstageVolumeResponse>
Client::call<NODE_UNSTAGE_VOLUME>(
    const NodeUnstageVolumeRequest& request);


template <>
process::Future<NodePublishVolumeResponse>
Client::call<NODE_PUBLISH_VOLUME>(
    const NodePublishVolumeRequest& request);


template <>
process::Future<NodeUnpublishVolumeResponse>
Client::call<NODE_UNPUBLISH_VOLUME>(
    const NodeUnpublishVolumeRequest& request);


template <>
process::Future<NodeGetIdResponse>
Client::call<NODE_GET_ID>(
    const NodeGetIdRequest& request);


template <>
process::Future<NodeGetCapabilitiesResponse>
Client::call<NODE_GET_CAPABILITIES>(
    const NodeGetCapabilitiesRequest& request);

} // namespace v0 {
} // namespace csi {
} // namespace mesos {

#endif // __CSI_CLIENT_HPP__
