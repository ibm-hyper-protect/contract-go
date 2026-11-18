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
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"

	gen "github.com/ibm-hyper-protect/contract-go/v3/common/general"
)

func TestUnsupportedRetrievableProfilesFailBeforeCrypto(t *testing.T) {
	// No crypto executable exists. Unsupported profiles must still fail with
	// the platform diagnosis, before touching keys or encryption certificates.
	t.Setenv("OPENSSL_BIN", filepath.Join(t.TempDir(), "not-installed"))
	certificate, _, _ := contractTestCertificate(t)
	options := retrievableTestOptions(certificate)
	environment, err := WithRetrievableSecrets(retrievableTestEnvironment, gen.ConfidentialComputingOsCcrv, options)
	if err != nil {
		t.Fatalf("offline CCRV preparation must not require OpenSSL or local UV hardware: %v", err)
	}
	pair := contractTestYAML(t, map[string]string{"env": environment, "workload": retrievableTestWorkload})
	for _, platform := range []string{"", gen.ConfidentialComputingOsCcrt, gen.HyperProtectOsHpvs, gen.ConfidentialComputingOsCcco, "unknown", "CCRV"} {
		t.Run("profile="+platform, func(t *testing.T) {
			if output, err := WithRetrievableSecrets(environment, platform, options); output != "" || err == nil || !strings.Contains(err.Error(), "RETRIEVABLE_SECRETS_UNSUPPORTED_PLATFORM") {
				t.Fatalf("builder did not reject the profile explicitly: %q, %v", output, err)
			}
			for _, input := range []struct{ text, section string }{{environment, SectionEnv}, {pair, SectionBoth}} {
				if err := HpcrVerifyContract(input.text, platform, input.section); err == nil || !strings.Contains(err.Error(), "RETRIEVABLE_SECRETS_UNSUPPORTED_PLATFORM") {
					t.Fatalf("validator did not reject the profile explicitly: %v", err)
				}
			}
			output, inHash, outHash, err := HpcrContractSignedEncrypted(pair, platform, "", "must-not-be-used", "must-not-be-used", "")
			if output != "" || inHash != "" || outHash != "" || err == nil || !strings.Contains(err.Error(), "RETRIEVABLE_SECRETS_UNSUPPORTED_PLATFORM") {
				t.Fatalf("unsupported contract reached the crypto path: %v", err)
			}
		})
	}
}

func TestUnsupportedPreparedRequestFormatsHaveClearErrors(t *testing.T) {
	fixture := preparedRequestFixtures(t)[0]
	for _, tc := range []struct {
		name, expected string
		edit           func([]byte)
	}{
		{"version", "RETRIEVABLE_SECRETS_UNSUPPORTED_REQUEST_VERSION", func(data []byte) { binary.BigEndian.PutUint32(data[8:12], 0x300) }},
		{"user-data type", "RETRIEVABLE_SECRETS_UNSUPPORTED_USER_DATA_TYPE", func(data []byte) { binary.BigEndian.PutUint16(data[6:8], 5) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := preparedRequestData(t, fixture)
			tc.edit(data)
			info, err := InspectPreparedSecretRequest(data)
			if info != (PreparedSecretRequestInfo{}) || err == nil || !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("unsupported format returned metadata or a generic error: %+v, %v", info, err)
			}
		})
	}
}
