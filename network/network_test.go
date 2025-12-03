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
	"testing"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
	"github.com/stretchr/testify/assert"
)

const (
	validNetworkConfigFile   = "../samples/network/network_config.yaml"
	invalidNetworkConfigFile = "../samples/network/network_config_invalid.yaml"
)

// Testcase to check if TestProcessNetworkSchemaValid() is able validate network-config
func TestProcessNetworkSchemaValid(t *testing.T) {
	network_config, err := gen.ReadDataFromFile(validNetworkConfigFile)
	if err != nil {
		t.Errorf("failed to read network config file - %v", err)
	}
	err = HpcrVerifyNetworkConfig(network_config)
	assert.NoError(t, err)
}

// Testcase to check if TestProcessNetworkSchemaInvalid() is able throw error with invalid network-config schema
func TestProcessNetworkSchemaInvalid(t *testing.T) {
	network_config_invalid, err := gen.ReadDataFromFile(invalidNetworkConfigFile)
	if err != nil {
		t.Errorf("failed to read network config file - %v", err)
	}
	err = HpcrVerifyNetworkConfig(network_config_invalid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "additionalProperties 'enc' not allowed")
}
