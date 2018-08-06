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

#include <string>

#include "master/resources/network_bandwidth.hpp"

#include <mesos/resources.hpp>

#include "slave/slave.hpp"

namespace mesos {
namespace resources {

using namespace std;

using mesos::internal::slave::Slave;

const string NETWORK_BANDWIDTH_LABEL_NAME = "NETWORK_BANDWIDTH_RESOURCE";

const string NETWORK_BANDWIDTH_RESOURCE_NAME = "network_bandwidth";
const string CPUS_RESOURCE_NAME = "cpus";

/**
 * @brief Return the first unreserved resource given its name.
 *
 * @param resources The set of resrouce to look into.
 * @param resourceName The name of the resource to find unreserved amount of.
 * @return The unreserved resource.
 */
Option<Resource> getUnreservedResource(
    const Resources& resources,
    const string& resourceName) {
  foreach(const Resource& resource, resources) {
    if(resource.name() == resourceName &&
       resource.allocation_info().role() == "*") {
      return resource;
    }
  }
  return None();
}


/**
 * @brief Return the first label matching a given key.
 *
 * @param labels The set of labels to look into.
 * @param labelKey The key of the label to find.
 * @return Return the label if it finds it otherwise None.
 */
Option<Label> getLabel(
    const Labels& labels,
    const string& labelKey) {
  foreach(const Label& label, labels.labels()) {
    if(label.key() == labelKey) {
      return label;
    }
  }
  return None();
}


/**
 * @brief Add network bandwidth to a task.
 *
 * @param task The task to add network bandwidth to.
 * @param amount The amount of network bandwidth in Mbps.
 */
void addNetworkBandwidth(TaskInfo& task, double amount) {
  // At this point, we declare the amount of network bandwidth relative to the
  // number of CPU shares.
  Resource* networkBandwidth = task.add_resources();
  networkBandwidth->set_name(NETWORK_BANDWIDTH_RESOURCE_NAME);
  networkBandwidth->set_type(mesos::Value::SCALAR);

  networkBandwidth->mutable_scalar()->set_value(amount);
  networkBandwidth->set_allocated_allocation_info(
        mesos::Resource_AllocationInfo().New());
  networkBandwidth->mutable_allocation_info()->set_role("*");
}


/**
 * @brief Compute the amount of network bandwidth relative to
 *   the share of reserved CPU and the network bandwidth declared on the
 *   slave.
 *
 * @param slaveTotalResources The global resources advertised by the slave.
 * @return The amount of network bandwidth relative to the share of reserved
 *   CPU.
 */
Try<Option<double>> computeNetworkBandwidthBasedOnShareOfCpu(
  const Resources& taskResources,
  const Resources& slaveTotalResources) {
  Option<Resource> totalNetworkBandwidth =
    getUnreservedResource(slaveTotalResources,
                          NETWORK_BANDWIDTH_RESOURCE_NAME);

  // No network bandwidth declared in the slave
  if(totalNetworkBandwidth.isNone()) {
    LOG(INFO) << "No network bandwidth advertised by the slave.";
    return Option<double>();
  }

  Option<Resource> totalCpus =
    getUnreservedResource(slaveTotalResources, CPUS_RESOURCE_NAME);
  Option<Resource> reservedCpus =
    getUnreservedResource(taskResources, CPUS_RESOURCE_NAME);

  if(totalCpus.isNone()) {
    return Error("No CPU advertised by the slave.");
  }

  if(reservedCpus.isNone()) {
    return Error("No CPU declared in the task. " \
                 "Cannot deduce network bandwidth.");
  }

  return reservedCpus.get().scalar().value() /
      totalCpus.get().scalar().value() *
      totalNetworkBandwidth.get().scalar().value();
}


/**
 * @brief Get an amount of network bandwidth, if any, from a set of labels.
 *
 * @param labels The set of labels to find network bandwidth amount in.
 * @return The amount of network bandwidth declared in the label if it is
 *   provided, None if the label is not provided and Error if there was
 *   an error while extracting the network bandwidth amount.
 */
Try<Option<double>> getNetworkBandwidthFromLabel(
  const Labels& labels) {
  Option<Label> networkBandwidthLabel =
    getLabel(labels, NETWORK_BANDWIDTH_LABEL_NAME);

  if(networkBandwidthLabel.isSome()) {
    LOG(INFO) << "Network bandwidth is specified in a label. " \
                 "Taking the value.";

    try {
      // Parse the amount of network bandwidth.
      return std::stof(
        networkBandwidthLabel.get().value());
    }
    catch(const std::invalid_argument&) {
      return Error("Invalid network bandwidth resource format. "\
                   "Should be an integer.");
    }
    catch(const std::out_of_range&) {
      return Error("Network bandwidth amount is out of range.");
    }
  }
  return Option<double>();
}


/**
 * @brief Enforce network bandwidth allocation (see header for more details).
 *
 * @param slaveTotalResources The resources declared on the slave.
 * @param task The task to enforce network bandwidth for.
 * @return Nothing if no enforcement is done or if it is successful, otherwise
 *  an Error.
 *
 * TODO(clems4ever): Be able to consume role resources as well as unreserved.
 */
Try<Nothing> enforceNetworkBandwidthAllocation(
    const Resources& slaveTotalResources,
    TaskInfo& task)
{
  // We first check if network bandwidth is already declared. In that case
  // we do not enforce allocation.
  Option<Resource> networkBandwidthResource =
    getUnreservedResource(task.resources(), NETWORK_BANDWIDTH_RESOURCE_NAME);

  if(networkBandwidthResource.isSome()) {
    LOG(INFO) << "Network bandwidth is specified in resources. " \
                 "No enforcement done.";
    return Nothing(); // Nothing to enforce if network bandwidth is declared.
  }

  // We then check if network bandwidth is provided by label in case of
  // schedulers not supporting network bandwidth offer matching.
  Try<Option<double>> networkBandwidthFromLabel =
      getNetworkBandwidthFromLabel(task.labels());

  if(networkBandwidthFromLabel.isError()) {
    return Error(networkBandwidthFromLabel.error());
  }

  if(networkBandwidthFromLabel.get().isSome()) {
    addNetworkBandwidth(task, networkBandwidthFromLabel.get().get());
    return Nothing();
  }

  // At this point, we enforce the network bandwidth allocation by reserving
  // network bandwidth relative to the share of CPU reserved on the slave.
  Try<Option<double>> defaultNetworkBandwidth =
      computeNetworkBandwidthBasedOnShareOfCpu(
        task.resources(),
        slaveTotalResources);

  if(defaultNetworkBandwidth.isError()) {
    return Error(defaultNetworkBandwidth.error());
  }

  if(defaultNetworkBandwidth.get().isSome()) {
    addNetworkBandwidth(task, defaultNetworkBandwidth.get().get());
  }
  return Nothing();
}

} // namespace resources {
} // namespace mesos {
