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
	"encoding/hex"
	"fmt"
	"strings"

	gen "github.com/ibm-hyper-protect/contract-go/v3/common/general"
	"gopkg.in/yaml.v3"
)

// RetrievableSecretRequest contains an already-created binary pvsecret request
// and its optional PEM or DER user-signature verification certificate. Data must
// contain the request file, never the plaintext secret or its YAML ID reference.
type RetrievableSecretRequest struct {
	Data        []byte
	Certificate []byte
	// ExpectedSecretID optionally checks the ID pinned during preparation.
	// Accepts exactly 32 bytes of hex, optionally prefixed with 0x. This is a
	// consistency check of public metadata, not request authentication.
	ExpectedSecretID string
}

// PreparedSecretRequestInfo contains the unverified public metadata of a
// prepared Association or retrievable-secret request. SecretID is the actual
// 0x-prefixed 32-byte UV ID, distinct from an alias, catalog UUID or index-N.
// It contains no plaintext secret or private key.
type PreparedSecretRequestInfo = gen.AddSecretRequestInfo

// InspectPreparedSecretRequest reads a prepared request's public secret ID, UV
// type, request version and request SHA-256 before workload/environment creation.
// It does not decrypt, authenticate, import or retrieve the secret.
//
// Parameters:
//   - data: Complete binary pvsecret request, not Base64 or an ID-reference YAML.
//
// Returns:
//   - Unverified public request metadata. Treat the reported type and ID as
//     claims until trusted pvsecret tooling and the target UV verify the request.
//   - Error for malformed requests or control requests without a secret ID.
func InspectPreparedSecretRequest(data []byte) (PreparedSecretRequestInfo, error) {
	return gen.InspectAddSecretRequest(data)
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
// Leave Hosts empty to reuse an existing host-attestation block; providing Hosts
// alongside an existing block is rejected rather than replacing it.
type RetrievableSecretsOptions struct {
	Requests []RetrievableSecretRequest
	Hosts    map[string]HostKeyDocument
	Lock     *bool
}

// WithRetrievableSecrets adds prepared requests and host key documents to raw
// environment YAML, then validates the complete environment. Existing logging,
// registry credentials, volumes and other fields are preserved. Existing
// uv-secrets blocks are rejected rather than overwritten. Existing host documents
// can be reused by leaving options.Hosts empty; they are still validated.
//
// Parameters:
//   - environment: One raw type: env YAML document.
//   - platform: Target platform; currently only "ccrv" supports this feature.
//   - options: Prepared binary requests, host documents and optional locking policy.
//
// Returns:
//   - Updated, validated raw environment YAML.
//   - Error for invalid/unsupported input, existing requests or conflicting hosts.
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
	if _, exists := section["uv-secrets"]; exists {
		return "", fmt.Errorf("environment already contains uv-secrets; edit the existing block explicitly")
	}
	_, hasHosts := section["host-attestation"]
	if hasHosts && len(options.Hosts) > 0 {
		return "", fmt.Errorf("environment already contains host-attestation; omit Hosts to reuse it")
	}
	lock := true
	if options.Lock != nil {
		lock = *options.Lock
	}
	requests := map[string]any{"lock": lock}
	for i, request := range options.Requests {
		if request.ExpectedSecretID != "" {
			expected, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(request.ExpectedSecretID), "0x"))
			if err != nil || len(expected) != 32 {
				return "", fmt.Errorf("request index-%d expected secret ID must be 32 bytes of hex", i+1)
			}
			info, err := InspectPreparedSecretRequest(request.Data)
			if err != nil {
				return "", fmt.Errorf("request index-%d metadata - %v", i+1, err)
			}
			if info.SecretID != fmt.Sprintf("0x%x", expected) {
				return "", fmt.Errorf("request index-%d does not match the expected secret ID", i+1)
			}
		}
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
	if !hasHosts {
		section["host-attestation"] = hosts
	}
	updated, err := yaml.Marshal(section)
	if err != nil {
		return "", fmt.Errorf("encode environment YAML - %v", err)
	}
	if err := HpcrVerifyContract(string(updated), platform, SectionEnv); err != nil {
		return "", err
	}
	return string(updated), nil
}
