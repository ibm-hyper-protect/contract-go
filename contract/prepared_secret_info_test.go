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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gen "github.com/ibm-hyper-protect/contract-go/v3/common/general"
)

type preparedRequestFixture struct {
	Name           string `json:"name"`
	File           string `json:"file"`
	RequestVersion uint32 `json:"request_version"`
	SecretType     uint16 `json:"secret_type"`
	SecretID       string `json:"secret_id"`
	RequestSHA256  string `json:"request_sha256"`
}

func preparedRequestFixtures(t testing.TB) []preparedRequestFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/prepared-secret-requests/metadata.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Requests []preparedRequestFixture `json:"requests"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Requests) != 15 {
		t.Fatal("expected fifteen IBM-created binary request fixtures")
	}
	return manifest.Requests
}

func preparedRequestData(t testing.TB, fixture preparedRequestFixture) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata/prepared-secret-requests", fixture.File))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestInspectPreparedSecretRequest(t *testing.T) {
	for _, fixture := range preparedRequestFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			data := preparedRequestData(t, fixture)
			original := bytes.Clone(data)
			info, err := InspectPreparedSecretRequest(data)
			if err != nil {
				t.Fatal(err)
			}
			if info.SecretID != fixture.SecretID || info.SecretType != fixture.SecretType ||
				info.RequestVersion != fixture.RequestVersion || info.RequestSHA256 != fixture.RequestSHA256 {
				t.Fatalf("metadata differs from IBM fixture reference: got %+v, fixture %+v", info, fixture)
			}
			if !bytes.Equal(data, original) {
				t.Fatal("inspecting metadata changed the prepared request")
			}
		})
	}
}

func TestPreparedSecretIDPinning(t *testing.T) {
	certificate, _, _ := contractTestCertificate(t)
	for _, fixture := range preparedRequestFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			request := preparedRequestData(t, fixture)
			for _, expected := range []string{fixture.SecretID, strings.TrimPrefix(fixture.SecretID, "0x"), strings.ToUpper(fixture.SecretID)} {
				options := retrievableTestOptions(certificate)
				options.Requests = []RetrievableSecretRequest{{Data: request, ExpectedSecretID: expected}}
				updated, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options)
				if err != nil {
					t.Fatal(err)
				}
				entry := contractTestMapping(t, updated)["uv-secrets"].(map[string]any)["index-1"].(map[string]any)
				if len(entry) != 2 {
					t.Fatal("expected metadata must not become unsupported contract fields")
				}
			}
			for _, expected := range []string{"0x", "wrong", strings.Repeat("a", 63), strings.Repeat("a", 64), strings.Repeat("a", 65), " " + fixture.SecretID, fixture.SecretID + "\n"} {
				options := retrievableTestOptions(certificate)
				options.Requests = []RetrievableSecretRequest{{Data: request, ExpectedSecretID: expected}}
				if updated, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options); err == nil || updated != "" {
					t.Fatal("mismatched or malformed pinned ID returned a contract")
				}
			}
		})
	}
}

func TestPreparedSecretRequestsCannotReuseAnID(t *testing.T) {
	certificate, _, _ := contractTestCertificate(t)
	fixture := preparedRequestFixtures(t)[0]
	request := preparedRequestData(t, fixture)
	changed := bytes.Clone(request)
	// Different request bytes still carry the same public ID. A real rotation
	// must use a distinct ID; changing ciphertext/nonces cannot create one.
	changed[len(changed)-1] ^= 1
	for _, second := range [][]byte{request, changed} {
		options := retrievableTestOptions(certificate)
		options.Requests = []RetrievableSecretRequest{{Data: request}, {Data: second}}
		if updated, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options); err == nil || updated != "" {
			t.Fatal("two requests with the same ID must not be assigned separate indices")
		}
	}
}

func TestPreparedSecretRequestsReuseProvidedHosts(t *testing.T) {
	certificate, _, _ := contractTestCertificate(t)
	options := retrievableTestOptions(certificate)
	withHosts, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options)
	if err != nil {
		t.Fatal(err)
	}
	env := contractTestMapping(t, withHosts)
	delete(env, "uv-secrets")
	input := contractTestYAML(t, env)
	if _, err := WithRetrievableSecrets(input, gen.ConfidentialComputingOsCcrv, options); err == nil {
		t.Fatal("provided host options must not silently replace existing hosts")
	}
	options.Hosts = nil
	updated, err := WithRetrievableSecrets(input, gen.ConfidentialComputingOsCcrv, options)
	if err != nil {
		t.Fatal(err)
	}
	result := contractTestMapping(t, updated)
	for field, value := range env {
		if contractTestYAML(t, value) != contractTestYAML(t, result[field]) {
			t.Fatalf("existing %s changed while reusing host documents", field)
		}
	}
	env["host-attestation"] = "not host documents"
	if updated, err := WithRetrievableSecrets(contractTestYAML(t, env), gen.ConfidentialComputingOsCcrv, options); err == nil || updated != "" {
		t.Fatal("invalid existing host documents were trusted implicitly")
	}
	if updated, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options); err == nil || updated != "" {
		t.Fatal("missing host documents accepted")
	}
}

func TestInspectPreparedSecretRequestBoundaries(t *testing.T) {
	for _, version := range []uint32{0x100, 0x200} {
		size := 1416
		if version == 0x200 {
			size = 2968
		}
		for _, kind := range []uint16{0, 1, 0x16} {
			request := retrievableTestRequest(version, size)
			// Use a listable-sized envelope but encode a control/reserved kind.
			binary.BigEndian.PutUint32(request[44:48], 64)
			offset := 1288
			if version == 0x200 {
				offset = 280
			}
			binary.BigEndian.PutUint16(request[offset+2:offset+4], kind)
			if info, err := InspectPreparedSecretRequest(request); err == nil || info != (PreparedSecretRequestInfo{}) {
				t.Fatal("control request returned a fabricated secret ID")
			}
		}
	}
	for _, fixture := range preparedRequestFixtures(t) {
		if fixture.Name != "plain-current" && fixture.Name != "hybrid-v2" {
			continue
		}
		request := preparedRequestData(t, fixture)
		for size := 0; size < len(request); size++ {
			if info, err := InspectPreparedSecretRequest(request[:size]); err == nil || info != (PreparedSecretRequestInfo{}) {
				t.Fatalf("truncated request accepted at %d bytes", size)
			}
		}
		// A changed GCM tag cannot be authenticated by this API. The ID stays
		// a public claim; its request checksum must change, not imply UV validity.
		changed := bytes.Clone(request)
		changed[len(changed)-1] ^= 1
		info, err := InspectPreparedSecretRequest(changed)
		if err != nil || info.SecretID != fixture.SecretID || info.RequestSHA256 == fixture.RequestSHA256 {
			t.Fatalf("incorrect unverified-metadata behavior: %+v, %v", info, err)
		}
		changed = append(bytes.Clone(request), 0)
		binary.BigEndian.PutUint32(changed[12:16], uint32(len(changed)))
		if _, err := InspectPreparedSecretRequest(changed); err == nil {
			t.Fatal("misaligned authenticated area accepted as secret metadata")
		}
	}
	certificate, _, _ := contractTestCertificate(t)
	options := retrievableTestOptions(certificate)
	options.Requests = []RetrievableSecretRequest{{Data: []byte("not a request"), ExpectedSecretID: strings.Repeat("a", 64)}}
	if updated, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options); err == nil || updated != "" {
		t.Fatal("malformed pinned request accepted")
	}
}

func FuzzInspectPreparedSecretRequest(f *testing.F) {
	for _, fixture := range preparedRequestFixtures(f) {
		f.Add(preparedRequestData(f, fixture))
	}
	f.Add([]byte("asrcbM"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, request []byte) {
		if len(request) > 65536 {
			t.Skip()
		}
		info, err := InspectPreparedSecretRequest(request)
		if err != nil && info != (PreparedSecretRequestInfo{}) {
			t.Fatal("partial metadata returned with an error")
		}
		if err == nil && len(info.SecretID) != 66 {
			t.Fatal("invalid UV secret ID length")
		}
	})
}
