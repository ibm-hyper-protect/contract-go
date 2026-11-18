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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	gen "github.com/ibm-hyper-protect/contract-go/v3/common/general"
	"gopkg.in/yaml.v3"
)

const retrievableTestEnvironment = "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-only\n    port: 443\nenv:\n  APP_MODE: test\nauths:\n  registry.example:\n    username: test-user\n    password: test-password\nvolumes:\n  data:\n    seed: EnvironmentSeed12345\n"
const retrievableTestWorkload = "type: workload\nplay:\n  archive: YWJjZA==\nvolumes:\n  data:\n    filesystem: ext4\n    mount: /mnt/data\n    seed: WorkloadSeed12345\n"

// Structurally representative, deliberately unauthenticated test requests.
// These fixtures never claim that a UV would accept their encrypted contents.
func retrievableTestRequest(version uint32, size int) []byte {
	data := make([]byte, size)
	copy(data, "asrcbM")
	binary.BigEndian.PutUint32(data[8:12], version)
	binary.BigEndian.PutUint32(data[12:16], uint32(size))
	data[39] = 1
	binary.BigEndian.PutUint32(data[44:48], 32)
	return data
}

func retrievableTestOptions(cert []byte) RetrievableSecretsOptions {
	return RetrievableSecretsOptions{
		Requests: []RetrievableSecretRequest{{Data: retrievableTestRequest(0x100, 1416), Certificate: cert}, {Data: retrievableTestRequest(0x200, 2968)}},
		Hosts: map[string]HostKeyDocument{
			"HKD-9175-0271A28": {Description: "Test host", Data: cert},
		},
	}
}

func TestWithRetrievableSecrets(t *testing.T) {
	cert, der, _ := contractTestCertificate(t)
	options := retrievableTestOptions(cert)
	options.Hosts["HKD-9175-0271A29"] = HostKeyDocument{Description: "Second test host", Data: der}
	text, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options)
	if err != nil {
		t.Fatal(err)
	}
	before, after := contractTestMapping(t, retrievableTestEnvironment), contractTestMapping(t, text)
	for key, value := range before {
		if !reflect.DeepEqual(value, after[key]) {
			t.Fatalf("existing %s changed", key)
		}
	}
	secrets := after["uv-secrets"].(map[string]any)
	if secrets["lock"] != true || len(secrets) != 3 {
		t.Fatal("expected default locking and two requests")
	}
	for i, expected := range options.Requests {
		entry := secrets[fmt.Sprintf("index-%d", i+1)].(map[string]any)
		actual, err := base64.StdEncoding.DecodeString(entry["pvsecret"].(string))
		if err != nil || !reflect.DeepEqual(actual, expected.Data) {
			t.Fatal("request bytes changed")
		}
	}
	if len(after["host-attestation"].(map[string]any)) != 2 {
		t.Fatal("second host was lost")
	}
	lock := false
	options.Lock = &lock
	text, err = WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options)
	if err != nil || contractTestMapping(t, text)["uv-secrets"].(map[string]any)["lock"] != false {
		t.Fatalf("explicit lock=false not preserved: %v", err)
	}
	if _, err := WithRetrievableSecrets(text, gen.ConfidentialComputingOsCcrv, options); err == nil {
		t.Fatal("existing requests must not be overwritten")
	}
	for count := 1; count <= 8; count++ {
		options.Requests = make([]RetrievableSecretRequest, count)
		for i := range options.Requests {
			options.Requests[i].Data = retrievableTestRequest(0x100, 1416+i*16)
		}
		if _, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options); err != nil {
			t.Fatalf("%d requests: %v", count, err)
		}
	}
	options.Requests = append(options.Requests, options.Requests[0])
	if _, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options); err == nil {
		t.Fatal("nine requests accepted")
	}
}

func TestRetrievableSecretValidation(t *testing.T) {
	cert, _, _ := contractTestCertificate(t)
	valid, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, retrievableTestOptions(cert))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(map[string]any)
	}{
		{"scalar block", func(env map[string]any) { env["uv-secrets"] = "wrong" }},
		{"null block", func(env map[string]any) { env["uv-secrets"] = nil }},
		{"empty block", func(env map[string]any) { env["uv-secrets"] = map[string]any{} }},
		{"invalid lock", func(env map[string]any) { env["uv-secrets"].(map[string]any)["lock"] = "false" }},
		{"unknown field", func(env map[string]any) { env["uv-secrets"].(map[string]any)["unknown"] = true }},
		{"index zero", func(env map[string]any) { s := env["uv-secrets"].(map[string]any); s["index-0"] = s["index-1"] }},
		{"index nine", func(env map[string]any) { s := env["uv-secrets"].(map[string]any); s["index-9"] = s["index-1"] }},
		{"index gap", func(env map[string]any) {
			s := env["uv-secrets"].(map[string]any)
			s["index-3"] = s["index-2"]
			delete(s, "index-2")
		}},
		{"missing first index", func(env map[string]any) { delete(env["uv-secrets"].(map[string]any), "index-1") }},
		{"null entry", func(env map[string]any) { env["uv-secrets"].(map[string]any)["index-1"] = nil }},
		{"missing host documents", func(env map[string]any) { delete(env, "host-attestation") }},
		{"empty host documents", func(env map[string]any) { env["host-attestation"] = map[string]any{} }},
		{"scalar host documents", func(env map[string]any) { env["host-attestation"] = "wrong" }},
		{"wrong host identifier", func(env map[string]any) {
			env["host-attestation"] = map[string]any{"wrong-host": map[string]any{"description": "x", "host-key-doc": base64.StdEncoding.EncodeToString(cert)}}
		}},
		{"wrong description type", func(env map[string]any) {
			env["host-attestation"].(map[string]any)["HKD-9175-0271A28"].(map[string]any)["description"] = 42
		}},
		{"invalid host certificate", func(env map[string]any) {
			env["host-attestation"].(map[string]any)["HKD-9175-0271A28"].(map[string]any)["host-key-doc"] = "bm90LWEtY2VydA=="
		}},
		{"host field typo", func(env map[string]any) {
			env["host-attestation"].(map[string]any)["HKD-9175-0271A28"].(map[string]any)["host-key-document"] = "wrong"
		}},
		{"missing secret reference", func(env map[string]any) {
			env["volumes"] = map[string]any{"data": map[string]any{"uv-secret-id": "index-3"}}
		}},
		{"missing previous secret reference", func(env map[string]any) {
			env["volumes"] = map[string]any{"data": map[string]any{"uv-secret-id": "index-1", "uv-previous-secret-id": "index-3"}}
		}},
		{"seed and secret reference", func(env map[string]any) {
			env["volumes"] = map[string]any{"data": map[string]any{"uv-secret-id": "index-1", "seed": "EnvironmentSeed12345"}}
		}},
		{"previous reference without current", func(env map[string]any) {
			env["volumes"] = map[string]any{"data": map[string]any{"uv-previous-secret-id": "index-1", "seed": "EnvironmentSeed12345"}}
		}},
		{"non-string reference", func(env map[string]any) {
			env["volumes"] = map[string]any{"data": map[string]any{"uv-secret-id": 1}}
		}},
	}
	for _, edit := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"wrong request type", func(s map[string]any) { s["type"] = "plain" }},
		{"missing request", func(s map[string]any) { delete(s, "pvsecret") }},
		{"null request", func(s map[string]any) { s["pvsecret"] = nil }},
		{"empty request", func(s map[string]any) { s["pvsecret"] = "" }},
		{"invalid base64", func(s map[string]any) { s["pvsecret"] = "%%%invalid" }},
		{"plaintext instead of request", func(s map[string]any) { s["pvsecret"] = base64.StdEncoding.EncodeToString([]byte("plaintext-secret")) }},
		{"unknown entry field", func(s map[string]any) { s["unknown"] = true }},
		{"invalid request certificate", func(s map[string]any) { s["pvsecret-crt"] = "bm90LWEtY2VydA==" }},
		{"invalid certificate base64", func(s map[string]any) { s["pvsecret-crt"] = "%%%invalid" }},
		{"empty request certificate", func(s map[string]any) { s["pvsecret-crt"] = "" }},
	} {
		edit := edit
		tests = append(tests, struct {
			name string
			edit func(map[string]any)
		}{edit.name, func(env map[string]any) { edit.edit(env["uv-secrets"].(map[string]any)["index-1"].(map[string]any)) }})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := contractTestMapping(t, valid)
			tc.edit(env)
			raw := contractTestYAML(t, env)
			pair := contractTestYAML(t, map[string]string{"env": raw, "workload": retrievableTestWorkload})
			for _, mode := range []struct{ text, section string }{{raw, SectionEnv}, {pair, SectionBoth}} {
				if err := HpcrVerifyContract(mode.text, gen.ConfidentialComputingOsCcrv, mode.section); err == nil {
					t.Fatalf("invalid input accepted in section mode %q", mode.section)
				}
			}
		})
	}
}

func TestRetrievableVolumeReferences(t *testing.T) {
	cert, _, _ := contractTestCertificate(t)
	text, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, retrievableTestOptions(cert))
	if err != nil {
		t.Fatal(err)
	}
	env := contractTestMapping(t, text)
	env["volumes"] = map[string]any{"data": map[string]any{"uv-secret-id": "index-1", "uv-previous-secret-id": "index-2"}}
	raw := contractTestYAML(t, env)
	if err := HpcrVerifyContract(raw, gen.ConfidentialComputingOsCcrv, SectionEnv); err != nil {
		t.Fatal(err)
	}
	pair := contractTestYAML(t, map[string]string{"env": raw, "workload": retrievableTestWorkload})
	if err := HpcrVerifyContract(pair, gen.ConfidentialComputingOsCcrv, SectionBoth); err != nil {
		t.Fatal(err)
	}
	pair = contractTestYAML(t, map[string]string{"env": raw, "workload": "type: workload\nplay:\n  archive: YWJjZA==\n"})
	if err := HpcrVerifyContract(pair, gen.ConfidentialComputingOsCcrv, SectionBoth); err == nil {
		t.Fatal("missing workload volume accepted")
	}
	delete(env, "uv-secrets")
	if err := HpcrVerifyContract(contractTestYAML(t, env), gen.ConfidentialComputingOsCcrv, SectionEnv); err == nil {
		t.Fatal("dangling reference without requests accepted")
	}
}

func TestRetrievableCertificateAndLockCompatibility(t *testing.T) {
	certificate, der, key := contractTestCertificate(t)
	expired := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "expired-request-test"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	expiredDER, err := x509.CreateCertificate(rand.Reader, expired, expired, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"omitted", nil, true},
		{"PEM", certificate, true},
		{"DER", der, true},
		// IBM documents a runtime warning, not rejection, for an expired request certificate.
		{"expired", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDER}), true},
		{"surrounding whitespace", append([]byte("\n "), append(certificate, '\n')...), true},
		{"leading garbage", append([]byte("garbage\n"), certificate...), false},
		{"trailing garbage", append(append([]byte{}, certificate...), []byte("garbage")...), false},
		{"bundle", append(append([]byte{}, certificate...), certificate...), false},
		{"wrong PEM label", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), false},
		{"PEM with invalid DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}), false},
		{"broken PEM", []byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), false},
		{"broken PEM before valid certificate", append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), certificate...), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := retrievableTestOptions(certificate)
			options.Requests[0].Certificate = tc.data
			updated, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if !tc.valid {
				return
			}
			environment := contractTestMapping(t, updated)
			delete(environment["uv-secrets"].(map[string]any), "lock")
			raw := contractTestYAML(t, environment)
			if err := HpcrVerifyContract(raw, gen.ConfidentialComputingOsCcrv, SectionEnv); err != nil {
				t.Fatalf("omitted lock: %v", err)
			}
			pair := contractTestYAML(t, map[string]string{"env": raw, "workload": retrievableTestWorkload})
			if err := HpcrVerifyContract(pair, gen.ConfidentialComputingOsCcrv, SectionBoth); err != nil {
				t.Fatalf("complete contract: %v", err)
			}
		})
	}
}

func TestRetrievableHostDocumentCertificates(t *testing.T) {
	certificate, der, _ := contractTestCertificate(t)
	second, _, _ := contractTestCertificate(t)
	bundle := append(append([]byte{}, certificate...), second...)
	brokenFirst := append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), certificate...)
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"single PEM", certificate, true},
		{"single DER", der, true},
		// s390-tools defines classical HKDs with one certificate and hybrid HKDs with two.
		{"two PEM certificates", bundle, true},
		{"empty", nil, false},
		{"three PEM certificates", append(append([]byte{}, bundle...), certificate...), false},
		{"broken first certificate", brokenFirst, false},
		{"garbage between certificates", append(append(append([]byte{}, certificate...), []byte("garbage\n")...), second...), false},
		{"truncated second certificate", append(append([]byte{}, certificate...), second[:len(second)/2]...), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := retrievableTestOptions(certificate)
			options.Hosts["HKD-9175-0271A28"] = HostKeyDocument{Description: "Test document", Data: tc.data}
			updated, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if !tc.valid {
				return
			}
			hosts := contractTestMapping(t, updated)["host-attestation"].(map[string]any)
			actual, err := base64.StdEncoding.DecodeString(hosts["HKD-9175-0271A28"].(map[string]any)["host-key-doc"].(string))
			if err != nil || !reflect.DeepEqual(actual, tc.data) {
				t.Fatal("host document bytes changed")
			}
			pair := contractTestYAML(t, map[string]string{"env": updated, "workload": retrievableTestWorkload})
			if err := HpcrVerifyContract(pair, gen.ConfidentialComputingOsCcrv, SectionBoth); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRetrievableSecretPlatformAndInputBoundaries(t *testing.T) {
	cert, _, _ := contractTestCertificate(t)
	options := retrievableTestOptions(cert)
	text, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"", gen.ConfidentialComputingOsCcrt, gen.HyperProtectOsHpvs, gen.ConfidentialComputingOsCcco, "unknown"} {
		if _, err := WithRetrievableSecrets(retrievableTestEnvironment, platform, options); err == nil {
			t.Fatalf("unsupported builder platform %q accepted", platform)
		}
		if err := HpcrVerifyContract(text, platform, SectionEnv); err == nil {
			t.Fatalf("unsupported validation platform %q accepted", platform)
		}
	}
	for _, input := range []string{"", "[]", "type: workload", retrievableTestEnvironment + "---\ntype: env\n", retrievableTestEnvironment + "type: env\n", text} {
		if _, err := WithRetrievableSecrets(input, gen.ConfidentialComputingOsCcrv, options); err == nil {
			t.Fatalf("invalid builder input accepted: %q", input)
		}
	}
	options.Requests = nil
	if _, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options); err == nil {
		t.Fatal("zero requests accepted")
	}
}

func TestRetrievableBuilderValidatesOriginalYAMLKeys(t *testing.T) {
	cert, _, _ := contractTestCertificate(t)
	options := retrievableTestOptions(cert)
	for _, tc := range []struct {
		name, contents string
		valid          bool
	}{
		{"non-string key", "  true: test\n", false},
		{"alias duplicate", "  FIRST: &variable_name SECOND\n  SECOND: 42\n  *variable_name: test\n", false},
		{"scalar alias", "  FIRST: &variable_name SECOND\n  *variable_name: test\n", true},
		{"merge override", "  <<: &defaults\n    FIRST: original\n  FIRST: replacement\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			environment := strings.Replace(retrievableTestEnvironment, "  APP_MODE: test\n", tc.contents, 1)
			updated, err := WithRetrievableSecrets(environment, gen.ConfidentialComputingOsCcrv, options)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t, error=%v", tc.valid, err)
			}
			if tc.valid && !reflect.DeepEqual(contractTestMapping(t, environment)["env"], contractTestMapping(t, updated)["env"]) {
				t.Fatal("builder changed environment variable values")
			}
		})
	}
}

func FuzzPreparedSecretBuilder(f *testing.F) {
	certificate, err := os.ReadFile("../samples/encryption-cert/active.crt")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(retrievableTestEnvironment, retrievableTestRequest(0x100, 1416))
	f.Add(retrievableTestEnvironment+"extension:\n  special: .nan\n  number: 100.0\n", retrievableTestRequest(0x100, 1416))
	f.Add("type: env\nenv: &cycle\n  VALUE: *cycle\n", []byte("asrcbM"))
	f.Fuzz(func(t *testing.T, environment string, request []byte) {
		if len(environment) > 16384 || len(request) > 16384 {
			t.Skip()
		}
		options := retrievableTestOptions(certificate)
		options.Requests = []RetrievableSecretRequest{{Data: request}}
		updated, err := WithRetrievableSecrets(environment, gen.ConfidentialComputingOsCcrv, options)
		if err != nil {
			return
		}
		if err := HpcrVerifyContract(updated, gen.ConfidentialComputingOsCcrv, SectionEnv); err != nil {
			t.Fatal("builder returned an invalid environment")
		}
		before, after := contractTestMapping(t, environment), contractTestMapping(t, updated)
		for field, original := range before {
			value, exists := after[field]
			// Canonical YAML also compares NaN values and resolved timestamp
			// representations, for which reflect.DeepEqual is unsuitable.
			if !exists || contractTestYAML(t, original) != contractTestYAML(t, value) {
				t.Fatalf("builder changed original environment field %s", field)
			}
		}
	})
}

func TestRetrievableContractEncryptedRoundTrip(t *testing.T) {
	cert, _, private := contractTestCertificate(t)
	environment, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, retrievableTestOptions(cert))
	if err != nil {
		t.Fatal(err)
	}
	// A block scalar at the end of a section can contain meaningful trailing
	// spaces and newlines. Encryption must preserve the validated YAML bytes.
	workload := retrievableTestWorkload + "env:\n  SECRET_VALUE: |+\n    preserved secret  \n\n"
	pair := contractTestYAML(t, map[string]string{"env": environment, "workload": workload})
	key := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}))
	signed, inputHash, outputHash, err := HpcrContractSignedEncrypted(pair, gen.ConfidentialComputingOsCcrv, "", string(cert), key, "")
	if err != nil {
		t.Fatal(err)
	}
	inputDigest, outputDigest := sha256.Sum256([]byte(pair)), sha256.Sum256([]byte(signed))
	if inputHash != fmt.Sprintf("%x", inputDigest) || outputHash != fmt.Sprintf("%x", outputDigest) {
		t.Fatal("incorrect contract checksums")
	}
	var result map[string]string
	if err := yaml.Unmarshal([]byte(signed), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result["env"], "contract-basic.") || strings.Contains(signed, "test-password") {
		t.Fatal("environment not encrypted")
	}
	cleartext, _, _, err := HpcrTextDecrypted(result["env"], key, "")
	if err != nil {
		t.Fatal(err)
	}
	before, after := contractTestMapping(t, environment), contractTestMapping(t, cleartext)
	for field, expected := range before {
		if !reflect.DeepEqual(expected, after[field]) {
			t.Fatalf("%s changed during signing/encryption", field)
		}
	}
	if _, exists := after["signingKey"]; !exists {
		t.Fatal("build signing key not injected")
	}
	decryptedWorkload, _, _, err := HpcrTextDecrypted(result["workload"], key, "")
	if err != nil {
		t.Fatal(err)
	}
	if decryptedWorkload != workload {
		t.Fatalf("workload bytes changed during encryption: got %q, want %q", decryptedWorkload, workload)
	}
	if !reflect.DeepEqual(contractTestMapping(t, workload), contractTestMapping(t, decryptedWorkload)) {
		t.Fatal("workload YAML values changed during encryption")
	}
	signature, err := base64.StdEncoding.DecodeString(result["envWorkloadSignature"])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(result["workload"] + result["env"]))
	if err := rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("contract signature: %v", err)
	}
	tampered := sha256.Sum256([]byte(result["workload"] + result["env"] + "changed"))
	if rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, tampered[:], signature) == nil {
		t.Fatal("tampering accepted")
	}
}
