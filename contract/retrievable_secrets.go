// Copyright (c) 2026 IBM Corp.
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

package contract

import (
	"encoding/base64"
	"fmt"

	gen "github.com/ibm-hyper-protect/contract-go/v3/common/general"
	"gopkg.in/yaml.v3"
)

// RetrievableSecretRequest contains an already-created binary pvsecret request
// and its optional PEM or DER user-signature verification certificate. Data must
// contain the request file, never the plaintext secret or its YAML ID reference.
type RetrievableSecretRequest struct {
	Data        []byte
	Certificate []byte
}

// HostKeyDocument contains a host key document and its description: one PEM or
// DER certificate for a classical HKD, or two PEM certificates for a hybrid HKD.
// Obtain it for the deployment host; it is distinct from the runtime encryption
// certificate and the optional request-signature verification certificate.
type HostKeyDocument struct {
	Description string
	Data        []byte
}

// RetrievableSecretsOptions configures prepared requests for a CCRV environment.
// Requests are assigned index-1 through index-8 in slice order. Hosts are keyed
// by their HKD-MODEL-PLANTSERIAL identifier. A nil Lock defaults to true, preventing
// further additions to the UV secret store after the runtime imports requests.
type RetrievableSecretsOptions struct {
	Requests []RetrievableSecretRequest
	Hosts    map[string]HostKeyDocument
	Lock     *bool
}

// WithRetrievableSecrets adds prepared requests and host key documents to raw
// environment YAML, then validates the complete environment. Existing logging,
// registry credentials, volumes and other fields are preserved. Existing
// uv-secrets or host-attestation blocks are rejected rather than overwritten.
//
// Parameters:
//   - environment: One raw type: env YAML document.
//   - platform: Target platform; currently only "ccrv" supports this feature.
//   - options: Prepared binary requests, host documents and optional locking policy.
//
// Returns:
//   - Updated, validated raw environment YAML.
//   - Error if input is invalid, unsupported or already contains either block.
//
// This function does not create requests, contact a host, verify HKD trust chains
// or authenticate requests. Those checks remain with trusted preparation tools
// and the target Secure Execution runtime and Ultravisor.
func WithRetrievableSecrets(environment, platform string, options RetrievableSecretsOptions) (string, error) {
	if platform != gen.ConfidentialComputingOsCcrv {
		return "", fmt.Errorf("retrievable secrets require the CCRV contract profile")
	}
	if len(options.Requests) == 0 || len(options.Requests) > 8 {
		return "", fmt.Errorf("provide between 1 and 8 prepared secret requests")
	}
	var section map[string]any
	if err := gen.DecodeContractYAML(environment, &section); err != nil {
		return "", fmt.Errorf("invalid environment YAML - %v", err)
	}
	if section["type"] != "env" {
		return "", fmt.Errorf("provide raw environment YAML starting with type: env")
	}
	for _, field := range []string{"uv-secrets", "host-attestation"} {
		if _, exists := section[field]; exists {
			return "", fmt.Errorf("environment already contains %s; edit the existing block explicitly", field)
		}
	}
	lock := true
	if options.Lock != nil {
		lock = *options.Lock
	}
	requests := map[string]any{"lock": lock}
	for i, request := range options.Requests {
		entry := map[string]any{"type": "pvsecret", "pvsecret": base64.StdEncoding.EncodeToString(request.Data)}
		if len(request.Certificate) > 0 {
			entry["pvsecret-crt"] = base64.StdEncoding.EncodeToString(request.Certificate)
		}
		requests[fmt.Sprintf("index-%d", i+1)] = entry
	}
	hosts := make(map[string]any, len(options.Hosts))
	for name, document := range options.Hosts {
		hosts[name] = map[string]any{"description": document.Description, "host-key-doc": base64.StdEncoding.EncodeToString(document.Data)}
	}
	section["uv-secrets"] = requests
	section["host-attestation"] = hosts
	updated, err := yaml.Marshal(section)
	if err != nil {
		return "", fmt.Errorf("encode environment YAML - %v", err)
	}
	if err := HpcrVerifyContract(string(updated), platform, SectionEnv); err != nil {
		return "", err
	}
	return string(updated), nil
}
