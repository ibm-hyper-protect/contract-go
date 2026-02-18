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

package decrypt

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	encryptedChecksumPath      = "../../samples/attestation/se-checksums.txt.enc"
	privateKeyPath             = "../../samples/attestation/private.pem"
	sampleAttestationRecordKey = "baseimage"

	encryptedTextPath        = "../../samples/decrypt/encrypt.txt"
	invalidEncryptedTextPath = "../../samples/decrypt/encrypt.invalid.txt"
	textPrivateKeyPath       = "../../samples/decrypt/private.key"
	decryptedText            = "hello-world"
)

// Testcase to check if DecryptPassword() is able to decrypt password
func TestDecryptPassword(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	encodedEncryptedData := strings.Split(encChecksum, ".")[1]

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	_, err = DecryptPassword(encodedEncryptedData, privateKeyData)
	if err != nil {
		t.Errorf("failed to decrypt password - %v", err)
	}
}

// Testcase to check if DecryptWorkload() is able to decrypt workload
func TestDecryptWorkload(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	encodedEncryptedPassword := strings.Split(encChecksum, ".")[1]
	encodedEncryptedData := strings.Split(encChecksum, ".")[2]

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	password, err := DecryptPassword(encodedEncryptedPassword, privateKeyData)
	if err != nil {
		t.Errorf("failed to decrypt password - %v", err)
	}

	result, err := DecryptWorkload(password, encodedEncryptedData)
	if err != nil {
		t.Errorf("failed to decrypt workload - %v", err)
	}

	assert.Contains(t, result, sampleAttestationRecordKey)
}

// Testcase to check if DecryptPassword() handles invalid private key
func TestDecryptPasswordInvalidPrivateKey(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	encodedEncryptedData := strings.Split(encChecksum, ".")[1]

	_, err = DecryptPassword(encodedEncryptedData, "invalid-private-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute openssl command")
}

// Testcase to check if DecryptWorkload() handles invalid base64 workload
func TestDecryptWorkloadInvalidBase64(t *testing.T) {
	_, err := DecryptWorkload("password", "invalid-base64-!@#$")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode base64")
}

// Testcase to check if DecryptPassword() handles empty base64 data
func TestDecryptPasswordEmptyBase64(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	_, err = DecryptPassword("", privateKey)
	assert.Error(t, err)
}

// Testcase to check if DecryptPassword() handles empty private key
func TestDecryptPasswordEmptyPrivateKey(t *testing.T) {
	_, err := DecryptPassword("dGVzdA==", "")
	assert.Error(t, err)
}

// Testcase to check if DecryptWorkload() handles empty password
func TestDecryptWorkloadEmptyPassword(t *testing.T) {
	_, err := DecryptWorkload("", "dGVzdA==")
	assert.Error(t, err)
}

// Testcase to check if DecryptWorkload() handles empty workload
func TestDecryptWorkloadEmptyWorkload(t *testing.T) {
	_, err := DecryptWorkload("password123", "")
	assert.Error(t, err)
}

// Testcase to check if DecryptPassword() handles success case with assertions
func TestDecryptPasswordSuccess(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	encodedEncryptedData := strings.Split(encChecksum, ".")[1]

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	result, err := DecryptPassword(encodedEncryptedData, privateKeyData)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if DecryptWorkload() handles success case with assertions
func TestDecryptWorkloadSuccess(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	encodedEncryptedPassword := strings.Split(encChecksum, ".")[1]
	encodedEncryptedData := strings.Split(encChecksum, ".")[2]

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	password, err := DecryptPassword(encodedEncryptedPassword, privateKeyData)
	assert.NoError(t, err)

	result, err := DecryptWorkload(password, encodedEncryptedData)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if DecryptPassword() handles malformed base64
func TestDecryptPasswordMalformedBase64(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	_, err = DecryptPassword("not-valid-base64!@#", privateKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode")
}

// Testcase to check if DecryptWorkload() handles malformed base64
func TestDecryptWorkloadMalformedBase64(t *testing.T) {
	_, err := DecryptWorkload("password123", "not-valid-base64!@#")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode")
}
