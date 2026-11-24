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
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	gen "github.com/ibm-hyper-protect/contract-go/v3/common/general"
)

const (
	encryptedChecksumPath       = "../../samples/attestation/se-checksums.txt.enc"
	privateKeyPath              = "../../samples/attestation/private.pem"
	encryptedPrivateKeyPath     = "../../samples/decrypt/private_encrypted.key"
	encryptedPublicKeyPath      = "../../samples/decrypt/public_encrypted.key"
	encryptedDataPath           = "../../samples/decrypt/encrypt_encrypted.txt"
	encryptedPrivateKeyPassword = "decryptpass"
	sampleAttestationRecordKey  = "baseimage"
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

	_, err = DecryptPassword(encodedEncryptedData, privateKeyData, "")
	if err != nil {
		t.Errorf("failed to decrypt password - %v", err)
	}
}

func TestDecryptPasswordPreservesBinaryBoundaryBytes(t *testing.T) {
	// Disposable PKCS#1 v1.5 ciphertext for the existing sample key. Its final
	// byte is FF (0x0c), which the text temporary-file helper would remove.
	const ciphertext = "fsXsPARJVK7xP7iYkHQt1KTP6fA8wkz4K13POG7s5suqr2mqRbGOt6L54yFLcb76SsM0hiE3x1vY9w3nwgJoV4YBWbSMR1tmuHPKJGC4oXLxKXlXM4X3tplsXMTr+V1njnFcPlcoC6k1sgZbVVynoeIWEogtlJDzixhsTUbZ+Rj5kE4w5m74lGDgstWM/+m/espCZtcCUH0BaMkOU02P5qI6LlEcRIhBYyrDboMxQ2Nwm1XdW/k0Q+9d8bxntcepHqWZRdMPGuTXYGI/sqmtfABj01Gxtjs6z/HHjgeOcrohT2CnRKOq3pYBWEM/n66VAbr5pTE+O54iSjVAzTUk8ukpSDVkgtWHrbLi2qSrM2VUW4vQshAcajmXnynGn/AUw04S55K/794/oodMushrUpecWzXs1G+l2QAbz1rIiQ5JINTypb6Ex1U0CtqhiNLMuFXQXVKyLyL4aFhetFVVaxQSnxI4YjDBRYYj8bH0p6qE6AizXVhvgVCzR+zkEqPCnl3tKieTtjlt9TPcXrnh1F5aogguwdHOTOd/F8IijaPNOvNqTUhSm9JqxH9y5pDm1O2PxBKwYIMnBOTe1E+JkRVIoZ8poV8oI44totY5QITRdpc+xMwxfVy0DmWZSxMhkXXiVDN0z/f5RROdzJXYxHA8vxOnN2qea/hRvoKFdgw="
	key, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	password, err := DecryptPassword(ciphertext, key, "")
	if err != nil || password != "binary boundary password 2" {
		t.Fatalf("binary RSA ciphertext was changed: %v", err)
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

	password, err := DecryptPassword(encodedEncryptedPassword, privateKeyData, "")
	if err != nil {
		t.Errorf("failed to decrypt password - %v", err)
	}

	result, err := DecryptWorkload(password, encodedEncryptedData)
	if err != nil {
		t.Errorf("failed to decrypt workload - %v", err)
	}

	assert.Contains(t, result, sampleAttestationRecordKey)
}

func TestDecryptWorkloadPreservesBinaryBoundaryBytes(t *testing.T) {
	// Fixed OpenSSL PBKDF2/AES fixtures for its 8- and 16-byte salt defaults.
	// Their final ciphertext bytes are LF and FF, which must never be trimmed.
	fixtures := map[int]string{
		8:  "U2FsdGVkX18BAgMEBQYHCJThSnnJ3H5P6QPGNkfE2/BRZflMgTs9ZFEJbZ76PNMK",
		16: "U2FsdGVkX18BAgMEBQYHCAkKCwwNDg8QJIIz/tqXgTZx7dzAXswGzqoRNyDMsJ1PZgNYUim1UQw=",
	}
	for saltLength, fixture := range fixtures {
		t.Run(fmt.Sprintf("salt-%d", saltLength), func(t *testing.T) {
			if saltLength == 16 {
				help, err := exec.Command(gen.GetOpenSSLPath(), "enc", "-help").CombinedOutput()
				if err != nil {
					t.Fatalf("cannot inspect OpenSSL options: %v", err)
				}
				if !strings.Contains(string(help), "-saltlen") {
					t.Skip("16-byte salts require OpenSSL 3.2+; 8-byte regression remains covered")
				}
			}
			clear, err := DecryptWorkload("test-password", fixture)
			if err != nil || clear != "binary boundary fixture 40" {
				t.Fatalf("binary ciphertext was changed: %v", err)
			}
		})
	}
}

// Testcase to check if DecryptPassword() handles invalid private key
func TestDecryptPasswordInvalidPrivateKey(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	encodedEncryptedData := strings.Split(encChecksum, ".")[1]

	_, err = DecryptPassword(encodedEncryptedData, "invalid-private-key", "")
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

	_, err = DecryptPassword("", privateKey, "")
	assert.Error(t, err)
}

// Testcase to check if DecryptPassword() handles empty private key
func TestDecryptPasswordEmptyPrivateKey(t *testing.T) {
	_, err := DecryptPassword("dGVzdA==", "", "")
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

	result, err := DecryptPassword(encodedEncryptedData, privateKeyData, "")
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

	password, err := DecryptPassword(encodedEncryptedPassword, privateKeyData, "")
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

	_, err = DecryptPassword("not-valid-base64!@#", privateKey, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode Base64")
}

// Testcase to check if DecryptWorkload() handles malformed base64
func TestDecryptWorkloadMalformedBase64(t *testing.T) {
	_, err := DecryptWorkload("password", "not-valid-base64!@#")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode base64")
}

// Testcase to check if DecryptText() works with valid encrypted data
func TestDecryptTextSuccess(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	result, err := DecryptText(encChecksum, privateKeyData, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, sampleAttestationRecordKey)
}

// Testcase to check if DecryptText() handles invalid private key
func TestDecryptTextInvalidPrivateKey(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	_, err = DecryptText(encChecksum, "invalid-private-key", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt password")
}

// Testcase to check if DecryptText() handles empty private key
func TestDecryptTextEmptyPrivateKey(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		t.Errorf("failed to read encrypted checksum - %v", err)
	}

	_, err = DecryptText(encChecksum, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt password")
}

// Testcase to check if DecryptText() handles malformed encrypted data
func TestDecryptTextMalformedData(t *testing.T) {
	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	_, err = DecryptText("hyper-protect-basic.invalid.data", privateKeyData, "")
	assert.Error(t, err)
}

// Testcase to check if DecryptPassword() works with password-protected private key
func TestDecryptPasswordWithEncryptedPrivateKey(t *testing.T) {
	// Read encrypted data
	encryptedData, err := gen.ReadDataFromFile(encryptedDataPath)
	if err != nil {
		t.Errorf("failed to read encrypted data - %v", err)
	}

	// Read password-protected private key
	privateKeyData, err := gen.ReadDataFromFile(encryptedPrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read encrypted private key - %v", err)
	}

	// Decrypt with correct password
	result, err := DecryptPassword(encryptedData, privateKeyData, encryptedPrivateKeyPassword)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if DecryptPassword() fails with wrong password for encrypted private key
func TestDecryptPasswordWithEncryptedPrivateKeyWrongPassword(t *testing.T) {
	// Read encrypted data
	encryptedData, err := gen.ReadDataFromFile(encryptedDataPath)
	if err != nil {
		t.Errorf("failed to read encrypted data - %v", err)
	}

	// Read password-protected private key
	privateKeyData, err := gen.ReadDataFromFile(encryptedPrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read encrypted private key - %v", err)
	}

	// Decrypt with wrong password - should fail
	_, err = DecryptPassword(encryptedData, privateKeyData, "wrongpassword")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute openssl command")
}

// Testcase to check if DecryptPassword() fails when password is required but not provided
func TestDecryptPasswordWithEncryptedPrivateKeyNoPassword(t *testing.T) {
	// Read encrypted data
	encryptedData, err := gen.ReadDataFromFile(encryptedDataPath)
	if err != nil {
		t.Errorf("failed to read encrypted data - %v", err)
	}

	// Read password-protected private key
	privateKeyData, err := gen.ReadDataFromFile(encryptedPrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read encrypted private key - %v", err)
	}

	// Decrypt without password - should fail with clear error message
	_, err = DecryptPassword(encryptedData, privateKeyData, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key is encrypted but no password provided")
}

// Testcase to check if DecryptPassword() successfully decrypts with password-protected key
func TestDecryptPasswordWithEncryptedPrivateKeySuccess(t *testing.T) {
	// Read encrypted data
	encryptedData, err := gen.ReadDataFromFile(encryptedDataPath)
	if err != nil {
		t.Errorf("failed to read encrypted data - %v", err)
	}

	// Read password-protected private key
	privateKeyData, err := gen.ReadDataFromFile(encryptedPrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read encrypted private key - %v", err)
	}

	// Decrypt with correct password
	result, err := DecryptPassword(encryptedData, privateKeyData, encryptedPrivateKeyPassword)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "Test encrypted data")
}

// Testcase to check if DecryptText() returns an error (not a panic) for a blob with no dots
func TestDecryptTextNoDots(t *testing.T) {
	_, err := DecryptText("nodotsinhere", "any-key", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse encrypted data")
}

// Testcase to check if DecryptText() returns an error (not a panic) for a blob with only one dot (2 segments)
func TestDecryptTextTwoSegments(t *testing.T) {
	_, err := DecryptText("hyper-protect-basic.onlyone", "any-key", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse encrypted data")
}

// Testcase to check if DecryptText() returns an error (not a panic) for an empty blob
func TestDecryptTextEmptyBlob(t *testing.T) {
	_, err := DecryptText("", "any-key", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse encrypted data")
}

// Testcase to check if DecryptText() returns an error (not a panic) for a blob with too many dots
func TestDecryptTextTooManySegments(t *testing.T) {
	_, err := DecryptText("hyper-protect-basic.pass.workload.extra", "any-key", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse encrypted data")
}
