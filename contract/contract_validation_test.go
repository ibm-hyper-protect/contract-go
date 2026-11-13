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
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"
	"time"

	gen "github.com/ibm-hyper-protect/contract-go/v3/common/general"
	"gopkg.in/yaml.v3"
)

func contractTestCertificate(t *testing.T) ([]byte, []byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable-contract-test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der, key
}

func contractTestMapping(t *testing.T, text string) map[string]any {
	t.Helper()
	var result map[string]any
	if err := yaml.Unmarshal([]byte(text), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func contractTestYAML(t *testing.T, value any) string {
	t.Helper()
	text, err := yaml.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

func TestContractSignInvalidSectionsReturnErrors(t *testing.T) {
	for _, input := range []string{
		"", "null", "{}", "[]", "env: value\n", "workload: value\n",
		"env: null\nworkload: value\n", "env: value\nworkload: 42\n",
		"env: value\nworkload: []\n", "env: ''\nworkload: value\n",
		"env: value\nworkload: '  '\n",
	} {
		t.Run(input, func(t *testing.T) {
			defer func() {
				if failure := recover(); failure != nil {
					t.Fatalf("invalid signing input panicked instead of returning an error: %v", failure)
				}
			}()
			if _, _, _, err := HpcrContractSign(input, "unused-invalid-key", ""); err == nil {
				t.Fatal("invalid signing input accepted")
			}
		})
	}
}

func TestContractSigningRejectsDiscardedInput(t *testing.T) {
	_, _, private := contractTestCertificate(t)
	key := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}))
	valid := "env: opaque-encrypted-env\nworkload: opaque-encrypted-workload\n"
	if _, _, _, err := HpcrContractSign(valid, key, ""); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		valid + "---\nenv: silently-discarded\n",
		valid + "attestationPublicKey: 42\n",
		valid + "attestationPublicKey: null\n",
		"env: &alias workload\n*alias: first\nworkload: second\n",
	} {
		if _, _, _, err := HpcrContractSign(input, key, ""); err == nil {
			t.Fatalf("signing silently discarded invalid input: %q", input)
		}
	}
}

func FuzzContractSigningInputs(f *testing.F) {
	// Valid shapes must fail cleanly too when the crypto executable is absent.
	f.Setenv("OPENSSL_BIN", f.TempDir()+"/not-installed")
	for _, input := range []string{"", "null", "{}", "env: value\nworkload: value\n", "env: value\nworkload: 42\n", "env: &label workload\n*label: one\nworkload: two\n"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 16384 {
			t.Skip()
		}
		output, inputHash, outputHash, err := HpcrContractSign(input, "unused-invalid-key", "")
		if err == nil || output != "" || inputHash != "" || outputHash != "" {
			t.Fatal("invalid or unavailable signing returned success/partial output")
		}
		if _, _, _, err := HpcrContractSignedEncrypted(input, gen.ConfidentialComputingOsCcrv, "", "invalid-certificate", "unused-invalid-key", ""); err == nil {
			t.Fatal("invalid encryption inputs accepted")
		}
	})
}

func TestWrappedContractRejectsAdditionalDocuments(t *testing.T) {
	for _, field := range []string{"env", "workload"} {
		sections := map[string]string{
			"env":      "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-only\n",
			"workload": "type: workload\nplay:\n  archive: YWJjZA==\n",
		}
		sections[field] += "---\ntype: " + field + "\n"
		for _, platform := range []string{gen.ConfidentialComputingOsCcrt, gen.ConfidentialComputingOsCcrv} {
			if err := HpcrVerifyContract(contractTestYAML(t, sections), platform, SectionBoth); err == nil {
				t.Fatalf("second %s document accepted for %s", field, platform)
			}
		}
	}
}

func TestContractEncryptedRoundTripPreservesBytes(t *testing.T) {
	certificate, _, private := contractTestCertificate(t)
	key := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}))
	environment := "type: env\nlogging:\n  logRouter:\n    hostname: logs.example.com\n    iamApiKey: test-only\n"
	workload := "type: workload\nplay:\n  archive: YWJjZA==\nenv:\n  VALUE: |+\n    preserved value  \n\n"
	input := contractTestYAML(t, map[string]string{"env": environment, "workload": workload})
	signed, _, _, err := HpcrContractSignedEncrypted(input, gen.ConfidentialComputingOsCcrv, "", string(certificate), key, "")
	if err != nil {
		t.Fatal(err)
	}
	var sections map[string]string
	if err := yaml.Unmarshal([]byte(signed), &sections); err != nil {
		t.Fatal(err)
	}
	decrypted, _, _, err := HpcrTextDecrypted(sections["workload"], key, "")
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != workload {
		t.Fatalf("workload bytes changed: got %q, want %q", decrypted, workload)
	}
	clearEnv, _, _, err := HpcrTextDecrypted(sections["env"], key, "")
	if err != nil {
		t.Fatal(err)
	}
	before, after := contractTestMapping(t, environment), contractTestMapping(t, clearEnv)
	delete(after, "signingKey")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("environment changed during encryption")
	}
	signature, err := base64.StdEncoding.DecodeString(sections["envWorkloadSignature"])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(sections["workload"] + sections["env"]))
	if err := rsa.VerifyPKCS1v15(&private.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal(err)
	}
}
