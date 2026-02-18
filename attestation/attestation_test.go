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
	"strings"
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

// Testcase to check if HpcrGetAttestationRecords() handles empty parameters
func TestHpcrGetAttestationRecordsEmptyData(t *testing.T) {
	_, err := HpcrGetAttestationRecords("", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), missingParameterErrStatement)
}

// Testcase to check if HpcrGetAttestationRecords() handles invalid private key
func TestHpcrGetAttestationRecordsInvalidPrivateKey(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to get encrypted checksum - %v", err)
	}

	_, err = HpcrGetAttestationRecords(encChecksum, "invalid-private-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt password")
}

// Testcase to check if HpcrGetAttestationRecords() handles decryption failure for attestation records
func TestHpcrGetAttestationRecordsDecryptWorkloadFailure(t *testing.T) {
	// Create a valid encrypted password but invalid encrypted data
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	// Use valid encrypted password but corrupt the encrypted data part
	parts := strings.Split(encChecksum, ".")
	corruptedData := parts[0] + "." + parts[1] + ".invalid-base64-data!@#"

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	_, err = HpcrGetAttestationRecords(corruptedData, privateKeyData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt attestation records")
}
