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

package general

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"sort"

	sch "github.com/ibm-hyper-protect/contract-go/v3/schema/contract"
)

// Structural validation runs after the platform schema. The Ultravisor remains
// responsible for authenticating requests and checking their SE-guest binding.
func validateRetrievableSecrets(contract map[string]any, platform string) error {
	env, ok := contract["env"].(map[string]any)
	if !ok {
		return nil
	}
	if platform != ConfidentialComputingOsCcrv {
		if _, exists := env["uv-secrets"]; exists {
			return fmt.Errorf("retrievable secrets require the CCRV contract profile")
		}
		return nil
	}
	if err := validateContractSchema(contract, sch.RetrievableSecretsSchemaCcrv); err != nil {
		return err
	}
	if err := validateHostAttestation(env); err != nil {
		return err
	}
	if _, hasSecrets := env["uv-secrets"]; hasSecrets {
		if err := validateUVSecrets(env); err != nil {
			return err
		}
	}
	workload, _ := contract["workload"].(map[string]any)
	return validateUVSecretReferences(env, workload)
}

func validateUVSecrets(env map[string]any) error {
	secrets := env["uv-secrets"].(map[string]any)
	seenRequests := make(map[[32]byte]string)
	seenIDs := make(map[string]string)
	for i := 1; i <= 8; i++ {
		name := fmt.Sprintf("index-%d", i)
		value, exists := secrets[name]
		if !exists {
			continue
		}
		entry := value.(map[string]any)
		request, err := decodeContractBase64(entry["pvsecret"].(string), "uv-secrets."+name+".pvsecret")
		if err != nil {
			return err
		}
		if err := validateAddSecretRequest(request); err != nil {
			return fmt.Errorf("uv-secrets.%s.pvsecret - %v", name, err)
		}
		digest := sha256.Sum256(request)
		if previous, exists := seenRequests[digest]; exists {
			return fmt.Errorf("uv-secrets.%s duplicates the request at %s", name, previous)
		}
		seenRequests[digest] = name
		// Only known listable layouts have an inspectable ID. Generic ASRCB
		// envelope validation remains independent of secret-specific semantics.
		if info, err := InspectAddSecretRequest(request); err == nil {
			if previous, exists := seenIDs[info.SecretID]; exists {
				return fmt.Errorf("uv-secrets.%s reuses the secret ID at %s", name, previous)
			}
			seenIDs[info.SecretID] = name
		}
		if certificate, exists := entry["pvsecret-crt"]; exists {
			if err := validateContractCertificate(certificate.(string), "uv-secrets."+name+".pvsecret-crt"); err != nil {
				return err
			}
		}
	}
	return nil
}

// Check the shared 48-byte ASRCB header described in s390-tools' RequestHdr.
// This deliberately does not implement request decryption or signature verification.
func validateAddSecretRequest(request []byte) error {
	if len(request) < 64 || !bytes.Equal(request[:6], []byte("asrcbM")) {
		return fmt.Errorf("expected a binary pvsecret add-secret request")
	}
	version := binary.BigEndian.Uint32(request[8:12])
	if version != 0x0100 && version != 0x0200 {
		return fmt.Errorf("unsupported add-secret request version")
	}
	if binary.BigEndian.Uint16(request[6:8]) > 4 {
		return fmt.Errorf("unsupported add-secret user-data type")
	}
	if uint64(binary.BigEndian.Uint32(request[12:16])) != uint64(len(request)) {
		return fmt.Errorf("add-secret request length does not match its header")
	}
	if request[39] == 0 {
		return fmt.Errorf("add-secret request must contain a host key slot")
	}
	confidentialLength := uint64(binary.BigEndian.Uint32(request[44:48]))
	// Header, authenticated data, user-data area, customer key and GCM tag.
	minimumOverhead := uint64(48 + 0x1e8 + 512 + 160 + 16)
	if version == 0x0100 {
		minimumOverhead += uint64(request[39])*80 + 16
	} else {
		minimumOverhead += uint64(request[39]) * 1680
	}
	if confidentialLength < 32 || minimumOverhead+confidentialLength > uint64(len(request)) {
		return fmt.Errorf("invalid add-secret confidential-data length")
	}
	return nil
}

// AddSecretRequestInfo contains unverified public metadata from a prepared
// add-secret request. SecretID is a 32-byte ID in 0x-prefixed lowercase hex;
// SecretType is the numeric Ultravisor type, not a catalog alias or contract index.
// RequestSHA256 hashes the complete binary request, not the secret value.
type AddSecretRequestInfo struct {
	RequestVersion uint32
	SecretType     uint16
	SecretID       string
	RequestSHA256  string
}

// InspectAddSecretRequest reads the public listable-secret header without
// decrypting the secret or authenticating the request.
//
// Parameters:
//   - request: Complete binary ASRCB file, not its Base64 or ID-reference YAML.
//
// Returns:
//   - Unverified metadata for an Association or retrievable-secret request.
//   - Error for malformed envelopes or requests without a listable secret ID.
func InspectAddSecretRequest(request []byte) (AddSecretRequestInfo, error) {
	if err := validateAddSecretRequest(request); err != nil {
		return AddSecretRequestInfo{}, err
	}
	version := binary.BigEndian.Uint32(request[8:12])
	confidentialLength := int(binary.BigEndian.Uint32(request[44:48]))
	authenticatedLength := len(request) - confidentialLength - 16
	// RequestHdr + ReqAuthData + user-data area + customer public key.
	keyslotsOffset := 48 + 0x1e8 + 512 + 160
	slots := int(request[39])
	headerOffset := keyslotsOffset + slots*80
	expectedLength := headerOffset + 48
	if version == 0x0200 {
		// ReqAuthDataV2 embeds the 48-byte secret header after flags,
		// BootHdrTags and ConfigUid, before its reserved area and key slots.
		headerOffset = 48 + 8 + 208 + 16
		expectedLength = keyslotsOffset + slots*1680
	}
	if authenticatedLength != expectedLength || headerOffset+48 > authenticatedLength {
		return AddSecretRequestInfo{}, fmt.Errorf("expected a complete listable-secret header")
	}
	kind := binary.BigEndian.Uint16(request[headerOffset+2 : headerOffset+4])
	// Null and Update-CCK are control requests; their header bytes are not IDs.
	if kind < 2 || kind == 0x0016 {
		return AddSecretRequestInfo{}, fmt.Errorf("request has no listable secret ID")
	}
	digest := sha256.Sum256(request)
	return AddSecretRequestInfo{
		RequestVersion: version,
		SecretType:     kind,
		SecretID:       fmt.Sprintf("0x%x", request[headerOffset+16:headerOffset+48]),
		RequestSHA256:  fmt.Sprintf("%x", digest),
	}, nil
}

func validateHostAttestation(env map[string]any) error {
	hosts, _ := env["host-attestation"].(map[string]any)
	for _, name := range sortedKeys(hosts) {
		entry := hosts[name].(map[string]any)
		if err := validateContractCertificates(entry["host-key-doc"].(string), "host-attestation."+name+".host-key-doc", 2); err != nil {
			return err
		}
	}
	return nil
}

func validateUVSecretReferences(env, workload map[string]any) error {
	secrets, _ := env["uv-secrets"].(map[string]any)
	volumes, _ := env["volumes"].(map[string]any)
	workloadVolumes, _ := workload["volumes"].(map[string]any)
	for _, name := range sortedKeys(volumes) {
		volume := volumes[name].(map[string]any)
		for _, field := range []string{"uv-secret-id", "uv-previous-secret-id"} {
			if reference, exists := volume[field]; exists {
				if _, found := secrets[reference.(string)]; !found {
					return fmt.Errorf("env.volumes.%s.%s must reference an entry in env.uv-secrets", name, field)
				}
				if workload != nil {
					if _, declared := workloadVolumes[name]; !declared {
						return fmt.Errorf("env volume %s has no workload volume declaration", name)
					}
				}
			}
		}
	}
	return nil
}

func decodeContractBase64(value, field string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return nil, fmt.Errorf("%s must contain non-empty Base64-encoded data", field)
	}
	return decoded, nil
}

func validateContractCertificate(value, field string) error {
	return validateContractCertificates(value, field, 1)
}

// Classical HKDs contain one certificate; hybrid HKDs contain two. Request
// verification certificates remain singular. This checks encoding, not trust
// chains, host identity, key algorithms or runtime support for a hybrid HKD.
func validateContractCertificates(value, field string, maximum int) error {
	decoded, err := decodeContractBase64(value, field)
	if err != nil {
		return err
	}
	invalid := fmt.Errorf("%s must contain one DER certificate or between 1 and %d PEM X.509 certificates", field, maximum)
	begin, end := []byte("-----BEGIN CERTIFICATE-----"), []byte("-----END CERTIFICATE-----")
	remaining := bytes.TrimSpace(decoded)
	if !bytes.HasPrefix(remaining, begin) {
		if _, err := x509.ParseCertificate(decoded); err != nil {
			return invalid
		}
		return nil
	}
	for count := 0; len(remaining) > 0; count++ {
		if count == maximum || !bytes.HasPrefix(remaining, begin) {
			return invalid
		}
		endOffset := bytes.Index(remaining, end)
		if endOffset < 0 {
			return invalid
		}
		encoded := remaining[:endOffset+len(end)]
		// pem.Decode skips malformed blocks. Decode only this first bounded
		// block so a later valid certificate cannot hide a broken one.
		block, rest := pem.Decode(encoded)
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || bytes.Count(encoded, begin) != 1 {
			return invalid
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return invalid
		}
		remaining = bytes.TrimSpace(remaining[len(encoded):])
	}
	return nil
}

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for name := range values {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}
