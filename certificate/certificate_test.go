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

package certificate

import (
	"testing"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
	"github.com/stretchr/testify/assert"
)

var (
	sampleJsonData = `{
		"1.0.0": {
			"cert": "data1",
			"status": "test1",
			"expiry_date": "26-02-26 12:27:33 GMT",
			"expiry_days": "1"
		},
		"4.0.0": {
			"cert": "data2",
			"status": "test2",
			"expiry_date": "26-02-26 12:27:33 GMT",
			"expiry_days": "2"
		}
	}`
	sampleEncryptionCertVersions       = []string{"1.0.20", "1.0.21", "1.0.22"}
	sampleInvalidEncryptionCertVersion = []string{"abc", "xy.z"}
	sampleCertDownloadTemplate         = "https://hpvsvpcubuntu.s3.us.cloud-object-storage.appdomain.cloud/s390x-{{.Patch}}/ibm-hyper-protect-container-runtime-{{.Major}}-{{.Minor}}-s390x-{{.Patch}}-encrypt.crt"

	sampleEncryptionCertPath = "../samples/encryption-cert/active.crt"

	sampleValidChainEncCertPath   = "../samples/certificate-chain/valid-chain/encryption.crt"
	sampleValidChainInterCertPath = "../samples/certificate-chain/valid-chain/intermediate.crt"
	sampleValidChainRootCertPath  = "../samples/certificate-chain/valid-chain/root.crt"

	sampleInvalidEncCertPath   = "../samples/certificate-chain/invalid-chain/encryption.crt"
	sampleInvalidInterCertPath = "../samples/certificate-chain/invalid-chain/wrong_intermediate.crt"
	sampleInvalidRootCertPath  = "../samples/certificate-chain/invalid-chain/root.crt"

	sampleExpiredEncCertPath   = "../samples/certificate-chain/expired-chain/expired_encryption.crt"
	sampleExpiredInterCertPath = "../samples/certificate-chain/expired-chain/intermediate.crt"
	sampleExpiredRootCertPath  = "../samples/certificate-chain/expired-chain/root.crt"
)

// Testcase to check if GetEncryptionCertificateFromJson() gets encryption certificate as per version constraint
func TestGetEncryptionCertificateFromJson(t *testing.T) {
	version := "> 1.0.0"

	key, cert, expiry_date, expiry_days, status, err := HpcrGetEncryptionCertificateFromJson(sampleJsonData, version)
	if err != nil {
		t.Errorf("failed to get encryption certificate from JSON - %v", err)
	}

	assert.Equal(t, key, "4.0.0")
	assert.Equal(t, cert, "data2")
	assert.Equal(t, expiry_date, "26-02-26 12:27:33 GMT")
	assert.Equal(t, expiry_days, "2")
	assert.Equal(t, status, "test2")
}

// Testcase to check if DownloadEncryptionCertificates() is able to download encryption certificates as per constraint
func TestDownloadEncryptionCertificates(t *testing.T) {
	certs, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "", "")
	if err != nil {
		t.Errorf("failed to download HPCR encryption certificates - %v", err)
	}

	assert.Contains(t, certs, "1.0.22")
}

// Testcase to check if DownloadEncryptionCertificates() is throwing error if no version is provided
func TestDownloadEncryptionCertificatesWithoutVersion(t *testing.T) {
	_, err := HpcrDownloadEncryptionCertificates([]string{}, "yaml", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required parameter is missing")
}

// Testcase to check if DownloadEncryptionCertificates() is able to download encryption certificates in YAML
func TestDownloadEncryptionCertificatesYaml(t *testing.T) {
	_, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "yaml", "")
	if err != nil {
		t.Errorf("failed to download HPCR encryption certificates - %v", err)
	}
}

// Testcase to check if DownloadEncryptionCertificates() is throwing error if version format is not correct
func TestDownloadEncryptionCertificatesWithInvalidVersionFormat(t *testing.T) {
	_, err := HpcrDownloadEncryptionCertificates(sampleInvalidEncryptionCertVersion, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version format: 'abc'. Expected comma-separated versions, e.g., 1.0.21 or 1.0.21,1.0.22")
}

// Testcase to check both DownloadEncryptionCertificates() and GetEncryptionCertificateFromJson() together
func TestCombined(t *testing.T) {
	certs, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "", sampleCertDownloadTemplate)
	if err != nil {
		t.Errorf("failed to download HPCR encryption certificates - %v", err)
	}

	version := "> 1.0.20"

	key, _, _, _, _, err := HpcrGetEncryptionCertificateFromJson(certs, version)
	if err != nil {
		t.Errorf("failed to get encryption certificate from JSON - %v", err)
	}

	assert.Equal(t, key, "1.0.22")
}

// Testcase to CheckEncryptionCertValidity() is able to validate encryption certificate
func TestHpcrDownloadEncryptionCertificates(t *testing.T) {
	encryptionCert, err := gen.ReadDataFromFile(sampleEncryptionCertPath)
	if err != nil {
		t.Errorf("failed to get encrypted checksum - %v", err)
	}
	_, err = HpcrValidateEncryptionCertificate(encryptionCert)
	assert.NoError(t, err)
}

// Testcase to check if HpcrGetEncryptionCertificateFromJson() handles empty parameters
func TestHpcrGetEncryptionCertificateFromJsonEmptyJson(t *testing.T) {
	_, _, _, _, _, err := HpcrGetEncryptionCertificateFromJson("", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), missingParameterErrStatement)
}

// Testcase to check if HpcrDownloadEncryptionCertificates() handles YAML format
func TestHpcrDownloadEncryptionCertificatesYamlFormat(t *testing.T) {
	result, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "yaml", sampleCertDownloadTemplate)
	if err != nil {
		t.Errorf("failed to download certificates in YAML format - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Contains(t, result, "1.0.20")
}

// Testcase to check if HpcrValidateCertChain validates certificate chain correctly
func TestHpcrValidateCertChain_ValidChain(t *testing.T) {
	// Using the active certificate from samples as encryption cert
	encCert, err := gen.ReadDataFromFile(sampleEncryptionCertPath)
	if err != nil {
		t.Errorf("failed to read encryption certificate - %v", err)
	}

	// For testing, we'll use the same cert as intermediate and root
	// This is a self-signed certificate, so OpenSSL will accept it
	intermediateCert := encCert
	rootCert := encCert

	valid, msg, err := HpcrValidateCertChain(encCert, intermediateCert, rootCert)

	// Self-signed certificate should validate successfully with OpenSSL
	assert.NoError(t, err)
	assert.True(t, valid)
	assert.NotEmpty(t, msg)
}

// Testcase to check if HpcrValidateCertChain handles empty parameters
func TestHpcrValidateCertChain_EmptyParameters(t *testing.T) {
	valid, msg, err := HpcrValidateCertChain("", "", "")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Empty(t, msg)
	assert.Contains(t, err.Error(), missingParameterErrStatement)
}

// Testcase to check if HpcrValidateCertChain handles invalid certificate format
func TestHpcrValidateCertChain_InvalidFormat(t *testing.T) {
	valid, msg, err := HpcrValidateCertChain("invalid", "cert", "data")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.NotEmpty(t, msg)
	// OpenSSL error messages may vary, so just check for error
}

// Testcase to check if HpcrCheckCertificateRevocation handles empty parameters
func TestHpcrCheckCertificateRevocation_EmptyParameters(t *testing.T) {
	revoked, msg, err := HpcrCheckCertificateRevocation("", "")
	assert.Error(t, err)
	assert.False(t, revoked)
	assert.Empty(t, msg)
	assert.Contains(t, err.Error(), missingParameterErrStatement)
}

// Testcase to check if HpcrCheckCertificateRevocation handles invalid certificate
func TestHpcrCheckCertificateRevocation_InvalidCert(t *testing.T) {
	revoked, msg, err := HpcrCheckCertificateRevocation("invalid", "crl")
	assert.Error(t, err)
	assert.False(t, revoked)
	assert.Empty(t, msg)
}

// Testcase to check if HpcrDownloadCRL handles empty URL
func TestHpcrDownloadCRL_EmptyURL(t *testing.T) {
	crl, err := HpcrDownloadCRL("")
	assert.Error(t, err)
	assert.Empty(t, crl)
	assert.Contains(t, err.Error(), missingParameterErrStatement)
}

// Testcase to check if HpcrDownloadCRL handles invalid URL
func TestHpcrDownloadCRL_InvalidURL(t *testing.T) {
	crl, err := HpcrDownloadCRL("http://invalid-url-that-does-not-exist.example.com/crl")
	assert.Error(t, err)
	assert.Empty(t, crl)
}

// Testcase to validate certificate chain with valid sample certificates
func TestHpcrValidateCertChain_WithSampleCerts_ValidChain(t *testing.T) {
	// Read valid certificate chain from samples
	encryptionCert, err := gen.ReadDataFromFile(sampleValidChainEncCertPath)
	if err != nil {
		t.Error("Failed to read encryption certificate")
	}

	intermediateCert, err := gen.ReadDataFromFile(sampleValidChainInterCertPath)
	if err != nil {
		t.Error("Failed to read Intermediate certificate")
	}

	rootCert, err := gen.ReadDataFromFile(sampleValidChainRootCertPath)
	if err != nil {
		t.Error("Failed to read root certificate")
	}

	// Validate the certificate chain
	valid, msg, err := HpcrValidateCertChain(string(encryptionCert), string(intermediateCert), string(rootCert))

	assert.NoError(t, err, "Validation should not return error for valid chain")
	assert.True(t, valid, "Certificate chain should be valid")
	assert.Contains(t, msg, "Certificate chain is valid", "Message should indicate valid chain")
	assert.Contains(t, msg, "expires on", "Message should include expiry information")
	t.Logf("Valid chain test passed: %s", msg)
}

// Testcase to validate certificate chain with invalid sample certificates (broken chain)
func TestHpcrValidateCertChain_WithSampleCerts_InvalidChain(t *testing.T) {
	// Read invalid certificate chain from samples (wrong intermediate)
	encryptionCert, err := gen.ReadDataFromFile(sampleInvalidEncCertPath)
	if err != nil {
		t.Error("Failed to read encryption certificate")
	}

	wrongIntermediateCert, err := gen.ReadDataFromFile(sampleInvalidInterCertPath)
	if err != nil {
		t.Error("Failed to read intermediate certificate")
	}

	rootCert, err := gen.ReadDataFromFile(sampleInvalidRootCertPath)
	if err != nil {
		t.Error("Failed to read root certificate")
	}

	// Try to validate the broken certificate chain
	valid, msg, err := HpcrValidateCertChain(string(encryptionCert), string(wrongIntermediateCert), string(rootCert))

	// We expect either an error or invalid result
	if err != nil {
		assert.Contains(t, err.Error(), "certificate chain validation failed", "Error should indicate validation failure")
		t.Logf("Correctly detected broken chain with error: %v", err)
	} else {
		assert.False(t, valid, "Certificate chain should be invalid")
		t.Logf("Correctly detected broken chain: %s", msg)
	}
}

// Testcase to validate expired certificate
func TestHpcrValidateCertChain_WithSampleCerts_ExpiredCert(t *testing.T) {
	// Read expired certificate from samples
	expiredEncryptionCert, err := gen.ReadDataFromFile(sampleExpiredEncCertPath)
	if err != nil {
		t.Error("Failed to read encryption certificate")
	}

	intermediateCert, err := gen.ReadDataFromFile(sampleExpiredInterCertPath)
	if err != nil {
		t.Error("Failed to read intermediate certificate")
	}

	rootCert, err := gen.ReadDataFromFile(sampleExpiredRootCertPath)
	if err != nil {
		t.Error("Failed to read root certificate")
	}

	// Try to validate the expired certificate
	valid, msg, err := HpcrValidateCertChain(string(expiredEncryptionCert), string(intermediateCert), string(rootCert))

	// We expect either an error or invalid result
	if err != nil {
		assert.Contains(t, err.Error(), "certificate chain validation failed", "Error should indicate validation failure")
		t.Logf("Correctly detected expired certificate with error: %v", err)
	} else {
		assert.False(t, valid, "Expired certificate should be invalid")
		t.Logf("Correctly detected expired certificate: %s", msg)
	}
}
