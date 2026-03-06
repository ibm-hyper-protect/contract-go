// Copyright (c) 2025 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package network

import (
	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

// HpcrVerifyNetworkConfig validates a network configuration YAML against the platform-specific schema.
//
// Use this function to validate the static IP network configuration for on-premise IBM Confidential
// Computing deployments before including it in a contract. This is particularly useful when deploying
// with DHCP-less, static IP configurations where the network settings must be validated against
// the platform schema to avoid deployment failures.
//
// Supported platforms:
//   - IBM Confidential Computing Container Runtime (HPVS)
//   - IBM Confidential Computing Container Runtime for Red Hat Virtualization Solutions (HPCR-RHVS)
//
// Parameters:
//   - network_config: Network configuration in YAML format (see samples/network/network_config.yaml for examples)
//
// Returns:
//   - nil if the network configuration is valid
//   - Error with details about what fields or formats are incorrect
func HpcrVerifyNetworkConfig(network_config string) error {
	return gen.VerifyNetworkSchema(network_config)
}
