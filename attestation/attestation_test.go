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
	invalidCert                = `-----BEGIN CERTIFICATE-----
invalid-certificate-data
-----END CERTIFICATE-----`
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

// Testcase to check HpcrVerifySignatureAttestationRecords parameter validation
func TestHpcrVerifySignatureAttestationRecords_ParameterValidation(t *testing.T) {
	// Test with empty attestation records
	err := HpcrVerifySignatureAttestationRecords("", []byte("signature"), "cert")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required parameter is missing")

	// Test with empty signature
	err = HpcrVerifySignatureAttestationRecords("records", []byte(""), "cert")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required parameter is missing")

	// Test with empty certificate
	err = HpcrVerifySignatureAttestationRecords("records", []byte("signature"), "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required parameter is missing")
}

// Testcase to check HpcrVerifySignatureAttestationRecords with valid parameters (positive test)
func TestHpcrVerifySignatureAttestationRecords_ValidParameters(t *testing.T) {
	attestationRecords := "test attestation records content"

	// Read the private key to create a certificate and sign data
	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to get private key - %v", err)
	}

	// Create a temporary file for the private key
	keyPath, err := gen.CreateTempFile(privateKeyData)
	if err != nil {
		t.Errorf("failed to create temp file - %v", err)
	}
	defer gen.RemoveTempFile(keyPath)

	// Generate a self-signed certificate
	cert, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "req", "-new", "-x509", "-key", keyPath, "-days", "365", "-subj", "/CN=Test")
	if err != nil {
		t.Errorf("failed to create certificate - %v", err)
	}

	// Create a temporary file for attestation records
	recordsPath, err := gen.CreateTempFile(attestationRecords)
	if err != nil {
		t.Errorf("failed to create attestation records temp file - %v", err)
	}
	defer gen.RemoveTempFile(recordsPath)

	// Sign the attestation records using the private key and write to temp file
	signatureStr, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "dgst", "-sha256", "-sign", keyPath, recordsPath)
	if err != nil {
		t.Errorf("failed to sign attestation records - %v", err)
	}

	// Convert signature string to bytes
	signature := []byte(signatureStr)

	// Verify the signature with valid parameters - should succeed
	err = HpcrVerifySignatureAttestationRecords(attestationRecords, signature, cert)
	assert.NoError(t, err, "Signature verification should succeed with valid parameters")
}

// Testcase to check HpcrVerifySignatureAttestationRecords with invalid PEM format
func TestHpcrVerifySignatureAttestationRecords_InvalidPEMFormat(t *testing.T) {
	err := HpcrVerifySignatureAttestationRecords("records", []byte("signature"), "invalid-cert")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract public key")
}

// Testcase to check HpcrVerifySignatureAttestationRecords with valid PEM but invalid certificate data
func TestHpcrVerifySignatureAttestationRecords_InvalidCertificateData(t *testing.T) {
	err := HpcrVerifySignatureAttestationRecords("records", []byte("signature"), invalidCert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract public key")
}

// Testcase to check HpcrVerifySignatureAttestationRecords with valid signature
func TestHpcrVerifySignatureAttestationRecords_ValidSignature(t *testing.T) {
	t.Skip("Skipping integration test - requires actual IBM attestation certificate and signature files")

	// This test would require actual se-signature.bin file from IBM attestation
	// For now, we test the function with parameter validation and error cases
	// In production, users will have the actual IBM attestation certificate and signature
}

// Testcase to check HpcrVerifySignatureAttestationRecords with invalid signature
func TestHpcrVerifySignatureAttestationRecords_InvalidSignature(t *testing.T) {
	attestationRecords := "test attestation records"
	invalidSignature := []byte("invalid signature data")

	// Create a test certificate
	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to get private key - %v", err)
	}

	certPath, err := gen.CreateTempFile(privateKeyData)
	if err != nil {
		t.Errorf("failed to create temp file - %v", err)
	}

	cert, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "req", "-new", "-x509", "-key", certPath, "-days", "365", "-subj", "/CN=Test")
	if err != nil {
		t.Errorf("failed to create certificate - %v", err)
	}

	err = gen.RemoveTempFile(certPath)
	if err != nil {
		t.Errorf("failed to remove temp file - %v", err)
	}

	// Verify with invalid signature should fail
	err = HpcrVerifySignatureAttestationRecords(attestationRecords, invalidSignature, cert)
	assert.Error(t, err, "Signature verification should fail with invalid signature")
	assert.Contains(t, err.Error(), "signature verification failed")
}
