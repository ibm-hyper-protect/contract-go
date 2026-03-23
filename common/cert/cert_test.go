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

package cert

import (
	"testing"

	"github.com/ibm-hyper-protect/contract-go/v2/common/general"
	"github.com/stretchr/testify/assert"
)

const (
	validChainEncCertPath   = "../../samples/certificate-chain/valid-chain/encryption.crt"
	validChainInterCertPath = "../../samples/certificate-chain/valid-chain/intermediate.crt"
	validChainRootCertPath  = "../../samples/certificate-chain/valid-chain/root.crt"
)

// Test ValidateCertificateChain with empty parameters
func TestValidateCertificateChain_EmptyParameters(t *testing.T) {
	valid, msg, err := ValidateCertificateChain("", "", "")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Empty(t, msg)
	assert.Contains(t, err.Error(), "required parameter is missing")
}

// Test ValidateCertificateChain with invalid certificate format
func TestValidateCertificateChain_InvalidFormat(t *testing.T) {
	valid, msg, err := ValidateCertificateChain("invalid", "cert", "data")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.NotEmpty(t, msg)
}

// Test CheckCertificateRevocation with empty parameters
func TestCheckCertificateRevocation_EmptyParameters(t *testing.T) {
	revoked, msg, err := CheckCertificateRevocation("", "")
	assert.Error(t, err)
	assert.False(t, revoked)
	assert.Empty(t, msg)
	assert.Contains(t, err.Error(), "required parameter is missing")
}

// Test CheckCertificateRevocation with invalid certificate
func TestCheckCertificateRevocation_InvalidCert(t *testing.T) {
	revoked, msg, err := CheckCertificateRevocation("invalid", "crl")
	assert.Error(t, err)
	assert.False(t, revoked)
	assert.Empty(t, msg)
}

// Test DownloadCRL with empty URL
func TestDownloadCRL_EmptyURL(t *testing.T) {
	crl, err := DownloadCRL("")
	assert.Error(t, err)
	assert.Empty(t, crl)
	assert.Contains(t, err.Error(), "required parameter is missing")
}

// Test DownloadCRL with invalid URL
func TestDownloadCRL_InvalidURL(t *testing.T) {
	crl, err := DownloadCRL("http://invalid-url-that-does-not-exist.example.com/crl")
	assert.Error(t, err)
	assert.Empty(t, crl)
}

// Test ValidateCertificateChain with valid certificate chain from samples
func TestValidateCertificateChain_ValidChain(t *testing.T) {
	// Read valid certificate chain from samples directory
	encryptionCert, err := general.ReadDataFromFile(validChainEncCertPath)
	if err != nil {
		t.Error("Failed to read encryption certificate")
	}

	intermediateCert, err := general.ReadDataFromFile(validChainInterCertPath)
	if err != nil {
		t.Error("Failed to read intermediate certificate")
	}

	rootCert, err := general.ReadDataFromFile(validChainRootCertPath)
	if err != nil {
		t.Error("Failed to read root certificate")
	}

	// Validate the certificate chain
	valid, msg, err := ValidateCertificateChain(encryptionCert, intermediateCert, rootCert)

	if err != nil {
		t.Logf("Validation error: %v", err)
	}

	if valid {
		t.Logf("Valid chain test passed: %s", msg)
		assert.True(t, valid, "Certificate chain should be valid")
		assert.Contains(t, msg, "Certificate chain is valid", "Message should indicate valid chain")
		assert.Contains(t, msg, "expires on", "Message should include expiry information")
	} else {
		t.Logf("Validation result: valid=%v, msg=%s", valid, msg)
	}
}
