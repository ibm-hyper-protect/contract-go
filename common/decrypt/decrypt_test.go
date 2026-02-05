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

	encryptedTextPath  = "../../samples/decrypt/encrypt.txt"
	textPrivateKeyPath = "../../samples/decrypt/private.key"
	decryptedText      = "hello-world"
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

func TestDecryptText(t *testing.T) {
	encryptedString, err := gen.ReadDataFromFile(encryptedTextPath)
	if err != nil {
		t.Errorf("failed to read encrypted data - %v", err)
	}

	privateKey, err := gen.ReadDataFromFile(textPrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	result, err := DecryptText(encryptedString, privateKey)
	if err != nil {
		t.Errorf("failed to decrypt text - %v", result)
	}

	assert.Equal(t, result, decryptedText)
}
