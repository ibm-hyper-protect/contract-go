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

package attestation

import (
	"testing"

	"github.com/stretchr/testify/assert"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	encryptedChecksumPath      = "../samples/attestation/se-checksums.txt.enc"
	privateKeyPath             = "../samples/attestation/private.pem"
	sampleAttestationRecordKey = "baseimage"
)

// Testcase to check if HpcrGetAttestationRecords() retrieves attestation records from encrypted data
func TestHpcrGetAttestationRecords(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to get encrypted checksum - %v", err)
	}

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to get private key - %v", err)
	}

	result, err := HpcrGetAttestationRecords(encChecksum, privateKeyData)
	if err != nil {
		t.Errorf("failed to decrypt attestation records - %v", err)
	}

	assert.Contains(t, result, sampleAttestationRecordKey)
}
