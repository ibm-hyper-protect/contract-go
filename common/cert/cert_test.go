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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ibm-hyper-protect/contract-go/v2/common/general"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	validChainEncCertPath   = "../../samples/certificate-chain/valid-chain/encryption.crt"
	validChainInterCertPath = "../../samples/certificate-chain/valid-chain/intermediate.crt"
	validChainRootCertPath  = "../../samples/certificate-chain/valid-chain/root.crt"

	invalidChainEncCertPath   = "../../samples/certificate-chain/invalid-chain/encryption.crt"
	invalidChainInterCertPath = "../../samples/certificate-chain/invalid-chain/wrong_intermediate.crt"
	invalidChainRootCertPath  = "../../samples/certificate-chain/invalid-chain/root.crt"

	expiredChainEncCertPath   = "../../samples/certificate-chain/expired-chain/expired_encryption.crt"
	expiredChainInterCertPath = "../../samples/certificate-chain/expired-chain/intermediate.crt"
	expiredChainRootCertPath  = "../../samples/certificate-chain/expired-chain/root.crt"
)

type docFixtureOptions struct {
	badEncryptionSignature  bool
	badAttestationSignature bool
	expiredEncryption       bool
	futureEncryption        bool
	expiredAttestation      bool
	futureAttestation       bool
	revokeEncryption        bool
	revokeAttestation       bool
	malformedCRL            bool
	invalidCRLSignature     bool
	missingEncryptionCRLDP  bool
	missingAttestationCRLDP bool
}

type docValidationFixture struct {
	encryptionCert           string
	attestationCert          string
	ibmIntermediateCert      string
	digicertIntermediateCert string
	digicertRootCert         string
}

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
	encryptionCert, err := general.ReadDataFromFile(validChainEncCertPath)
	require.NoError(t, err)

	intermediateCert, err := general.ReadDataFromFile(validChainInterCertPath)
	require.NoError(t, err)

	rootCert, err := general.ReadDataFromFile(validChainRootCertPath)
	require.NoError(t, err)

	valid, msg, err := ValidateCertificateChain(encryptionCert, intermediateCert, rootCert)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.Contains(t, msg, "Certificate chain is valid")
	assert.Contains(t, msg, "expires on")
}

// Test ValidateCertificateChain with broken chain from samples
func TestValidateCertificateChain_InvalidChain(t *testing.T) {
	encryptionCert, err := general.ReadDataFromFile(invalidChainEncCertPath)
	require.NoError(t, err)

	intermediateCert, err := general.ReadDataFromFile(invalidChainInterCertPath)
	require.NoError(t, err)

	rootCert, err := general.ReadDataFromFile(invalidChainRootCertPath)
	require.NoError(t, err)

	valid, msg, err := ValidateCertificateChain(encryptionCert, intermediateCert, rootCert)
	if err != nil {
		assert.Contains(t, err.Error(), "certificate chain validation failed")
		return
	}

	assert.False(t, valid)
	assert.NotEmpty(t, msg)
}

// Test ValidateCertificateChain with expired leaf certificate from samples
func TestValidateCertificateChain_ExpiredLeaf(t *testing.T) {
	encryptionCert, err := general.ReadDataFromFile(expiredChainEncCertPath)
	require.NoError(t, err)

	intermediateCert, err := general.ReadDataFromFile(expiredChainInterCertPath)
	require.NoError(t, err)

	rootCert, err := general.ReadDataFromFile(expiredChainRootCertPath)
	require.NoError(t, err)

	valid, msg, err := ValidateCertificateChain(encryptionCert, intermediateCert, rootCert)
	if err != nil {
		assert.Contains(t, err.Error(), "certificate chain validation failed")
		return
	}

	assert.False(t, valid)
	assert.NotEmpty(t, msg)
}

func TestValidateEncryptionCertificateDocument(t *testing.T) {
	testCases := []struct {
		name       string
		opts       docFixtureOptions
		mutate     func(f *docValidationFixture)
		errorStage string
	}{
		{
			name: "Valid",
		},
		{
			name: "BadRootIntermediateLink",
			mutate: func(f *docValidationFixture) {
				f.digicertRootCert = f.encryptionCert
			},
			errorStage: stageCAVerify,
		},
		{
			name:       "BadSignature",
			opts:       docFixtureOptions{badEncryptionSignature: true},
			errorStage: stageDocSignatureVerify,
		},
		{
			name:       "Expired",
			opts:       docFixtureOptions{expiredEncryption: true},
			errorStage: stageDateVerify,
		},
		{
			name:       "NotYetValid",
			opts:       docFixtureOptions{futureEncryption: true},
			errorStage: stageDateVerify,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fixture := newDocValidationFixture(t, tc.opts)
			if tc.mutate != nil {
				tc.mutate(fixture)
			}

			valid, msg, err := ValidateEncryptionCertificateDocument(
				fixture.encryptionCert,
				fixture.ibmIntermediateCert,
				fixture.digicertIntermediateCert,
				fixture.digicertRootCert,
			)

			if tc.errorStage == "" {
				require.NoError(t, err)
				assert.True(t, valid)
				assert.Contains(t, msg, "encryption certificate document is valid")
				return
			}

			require.Error(t, err)
			assert.False(t, valid)
			assert.Empty(t, msg)
			assert.Contains(t, err.Error(), tc.errorStage)
		})
	}
}

func TestValidateAttestationCertificateDocument(t *testing.T) {
	testCases := []struct {
		name       string
		opts       docFixtureOptions
		mutate     func(f *docValidationFixture)
		errorStage string
	}{
		{
			name: "Valid",
		},
		{
			name: "BadRootIntermediateLink",
			mutate: func(f *docValidationFixture) {
				f.digicertRootCert = f.attestationCert
			},
			errorStage: stageCAVerify,
		},
		{
			name:       "BadSignature",
			opts:       docFixtureOptions{badAttestationSignature: true},
			errorStage: stageDocSignatureVerify,
		},
		{
			name:       "Expired",
			opts:       docFixtureOptions{expiredAttestation: true},
			errorStage: stageDateVerify,
		},
		{
			name:       "NotYetValid",
			opts:       docFixtureOptions{futureAttestation: true},
			errorStage: stageDateVerify,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fixture := newDocValidationFixture(t, tc.opts)
			if tc.mutate != nil {
				tc.mutate(fixture)
			}

			valid, msg, err := ValidateAttestationCertificateDocument(
				fixture.attestationCert,
				fixture.ibmIntermediateCert,
				fixture.digicertIntermediateCert,
				fixture.digicertRootCert,
			)

			if tc.errorStage == "" {
				require.NoError(t, err)
				assert.True(t, valid)
				assert.Contains(t, msg, "attestation certificate document is valid")
				return
			}

			require.Error(t, err)
			assert.False(t, valid)
			assert.Empty(t, msg)
			assert.Contains(t, err.Error(), tc.errorStage)
		})
	}
}

func TestValidateCertificateRevocationList(t *testing.T) {
	testCases := []struct {
		name       string
		opts       docFixtureOptions
		errorStage string
	}{
		{
			name: "Valid",
		},
		{
			name:       "EncryptionRevoked",
			opts:       docFixtureOptions{revokeEncryption: true},
			errorStage: stageSerialRevoked,
		},
		{
			name:       "AttestationRevoked",
			opts:       docFixtureOptions{revokeAttestation: true},
			errorStage: stageSerialRevoked,
		},
		{
			name:       "InvalidCRLSignature",
			opts:       docFixtureOptions{invalidCRLSignature: true},
			errorStage: stageCRLSignatureVerify,
		},
		{
			name:       "MalformedCRL",
			opts:       docFixtureOptions{malformedCRL: true},
			errorStage: stageCRLSignatureVerify,
		},
		{
			name: "MissingCRLDistributionPoint",
			opts: docFixtureOptions{
				missingEncryptionCRLDP:  true,
				missingAttestationCRLDP: true,
			},
			errorStage: stageCRLSignatureVerify,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fixture := newDocValidationFixture(t, tc.opts)

			valid, msg, err := ValidateCertificateRevocationList(
				fixture.encryptionCert,
				fixture.attestationCert,
				fixture.ibmIntermediateCert,
			)

			if tc.errorStage == "" {
				require.NoError(t, err)
				assert.True(t, valid)
				assert.Contains(t, msg, "not revoked")
				return
			}

			require.Error(t, err)
			assert.False(t, valid)
			assert.Empty(t, msg)
			assert.Contains(t, err.Error(), tc.errorStage)
		})
	}
}

func newDocValidationFixture(t *testing.T, opts docFixtureOptions) *docValidationFixture {
	t.Helper()

	tempDir := t.TempDir()

	rootCRLPath := filepath.Join(tempDir, "root.crl")
	digiCRLPath := filepath.Join(tempDir, "digicert.crl")
	ibmCRLPath := filepath.Join(tempDir, "ibm.crl")

	rootCRLURL := (&url.URL{Scheme: "file", Path: rootCRLPath}).String()
	digiCRLURL := (&url.URL{Scheme: "file", Path: digiCRLPath}).String()
	ibmCRLURL := (&url.URL{Scheme: "file", Path: ibmCRLPath}).String()

	now := time.Now().UTC()

	rootKey := mustGenerateRSAKey(t)
	rootTemplate := caTemplate(t, "Test DigiCert Root", big.NewInt(100), now.Add(-2*time.Hour), now.Add(72*time.Hour), nil, nil, 2)
	rootDER := mustCreateCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	rootCert := mustParseCertificate(t, rootDER)

	digicertIntermediateKey := mustGenerateRSAKey(t)
	digicertIntermediateTemplate := caTemplate(
		t,
		"Test DigiCert Intermediate",
		big.NewInt(200),
		now.Add(-2*time.Hour),
		now.Add(72*time.Hour),
		[]string{rootCRLURL},
		rootCert.SubjectKeyId,
		1,
	)
	digicertIntermediateDER := mustCreateCertificate(t, digicertIntermediateTemplate, rootCert, &digicertIntermediateKey.PublicKey, rootKey)
	digicertIntermediateCert := mustParseCertificate(t, digicertIntermediateDER)

	ibmIntermediateKey := mustGenerateRSAKey(t)
	ibmIntermediateTemplate := caTemplate(
		t,
		"Test IBM Intermediate",
		big.NewInt(300),
		now.Add(-2*time.Hour),
		now.Add(72*time.Hour),
		[]string{digiCRLURL},
		digicertIntermediateCert.SubjectKeyId,
		0,
	)
	ibmIntermediateDER := mustCreateCertificate(t, ibmIntermediateTemplate, digicertIntermediateCert, &ibmIntermediateKey.PublicKey, digicertIntermediateKey)
	ibmIntermediateCert := mustParseCertificate(t, ibmIntermediateDER)

	encryptionKey := mustGenerateRSAKey(t)
	attestationKey := mustGenerateRSAKey(t)

	encryptionTemplate := leafTemplate(t, "Test Encryption Certificate", big.NewInt(400), now, opts.expiredEncryption, opts.futureEncryption, !opts.missingEncryptionCRLDP, ibmCRLURL, ibmIntermediateCert.SubjectKeyId)
	attestationTemplate := leafTemplate(t, "Test Attestation Certificate", big.NewInt(500), now, opts.expiredAttestation, opts.futureAttestation, !opts.missingAttestationCRLDP, ibmCRLURL, ibmIntermediateCert.SubjectKeyId)

	encryptionParent := ibmIntermediateCert
	encryptionSigner := ibmIntermediateKey
	if opts.badEncryptionSignature {
		outsiderKey := mustGenerateRSAKey(t)
		outsiderTemplate := caTemplate(t, "Outsider CA", big.NewInt(600), now.Add(-2*time.Hour), now.Add(72*time.Hour), nil, nil, 0)
		outsiderDER := mustCreateCertificate(t, outsiderTemplate, outsiderTemplate, &outsiderKey.PublicKey, outsiderKey)
		encryptionParent = mustParseCertificate(t, outsiderDER)
		encryptionSigner = outsiderKey
	}

	attestationParent := ibmIntermediateCert
	attestationSigner := ibmIntermediateKey
	if opts.badAttestationSignature {
		outsiderKey := mustGenerateRSAKey(t)
		outsiderTemplate := caTemplate(t, "Outsider Attestation CA", big.NewInt(700), now.Add(-2*time.Hour), now.Add(72*time.Hour), nil, nil, 0)
		outsiderDER := mustCreateCertificate(t, outsiderTemplate, outsiderTemplate, &outsiderKey.PublicKey, outsiderKey)
		attestationParent = mustParseCertificate(t, outsiderDER)
		attestationSigner = outsiderKey
	}

	encryptionDER := mustCreateCertificate(t, encryptionTemplate, encryptionParent, &encryptionKey.PublicKey, encryptionSigner)
	attestationDER := mustCreateCertificate(t, attestationTemplate, attestationParent, &attestationKey.PublicKey, attestationSigner)

	encryptionCert := mustParseCertificate(t, encryptionDER)
	attestationCert := mustParseCertificate(t, attestationDER)

	rootCRLDER := mustCreateCRL(t, rootCert, rootKey, nil, now)
	digicertCRLDER := mustCreateCRL(t, digicertIntermediateCert, digicertIntermediateKey, nil, now)

	revoked := make([]*big.Int, 0, 2)
	if opts.revokeEncryption {
		revoked = append(revoked, encryptionCert.SerialNumber)
	}
	if opts.revokeAttestation {
		revoked = append(revoked, attestationCert.SerialNumber)
	}

	ibmCRLSigner := ibmIntermediateKey
	if opts.invalidCRLSignature {
		ibmCRLSigner = mustGenerateRSAKey(t)
	}
	ibmCRLDER := mustCreateCRL(t, ibmIntermediateCert, ibmCRLSigner, revoked, now)

	if opts.malformedCRL {
		require.NoError(t, os.WriteFile(ibmCRLPath, []byte("malformed-crl"), 0600))
	} else {
		require.NoError(t, os.WriteFile(ibmCRLPath, ibmCRLDER, 0600))
	}
	require.NoError(t, os.WriteFile(rootCRLPath, rootCRLDER, 0600))
	require.NoError(t, os.WriteFile(digiCRLPath, digicertCRLDER, 0600))

	return &docValidationFixture{
		encryptionCert:           pemEncodeCert(encryptionDER),
		attestationCert:          pemEncodeCert(attestationDER),
		ibmIntermediateCert:      pemEncodeCert(ibmIntermediateDER),
		digicertIntermediateCert: pemEncodeCert(digicertIntermediateDER),
		digicertRootCert:         pemEncodeCert(rootDER),
	}
}

func mustGenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func caTemplate(t *testing.T, commonName string, serial *big.Int, notBefore, notAfter time.Time, crlDP []string, authorityKeyID []byte, maxPathLen int) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Test Org"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    x509.SHA512WithRSA,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        maxPathLen == 0,
		MaxPathLen:            maxPathLen,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: crlDP,
		SubjectKeyId:          mustRandomBytes(t, 20),
		AuthorityKeyId:        authorityKeyID,
	}
}

func leafTemplate(t *testing.T, commonName string, serial *big.Int, now time.Time, expired, future, includeCRLDP bool, crlDP string, authorityKeyID []byte) *x509.Certificate {
	t.Helper()

	notBefore := now.Add(-2 * time.Hour)
	notAfter := now.Add(24 * time.Hour)
	switch {
	case expired:
		notBefore = now.Add(-48 * time.Hour)
		notAfter = now.Add(-2 * time.Hour)
	case future:
		notBefore = now.Add(2 * time.Hour)
		notAfter = now.Add(48 * time.Hour)
	}

	var crlDistributionPoints []string
	if includeCRLDP {
		crlDistributionPoints = []string{crlDP}
	}

	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Test Org"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    x509.SHA512WithRSA,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		CRLDistributionPoints: crlDistributionPoints,
		AuthorityKeyId:        authorityKeyID,
		SubjectKeyId:          mustRandomBytes(t, 20),
	}
}

func mustCreateCertificate(t *testing.T, template, parent *x509.Certificate, publicKey *rsa.PublicKey, parentKey *rsa.PrivateKey) []byte {
	t.Helper()
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	require.NoError(t, err)
	return certDER
}

func mustParseCertificate(t *testing.T, certDER []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func mustCreateCRL(t *testing.T, issuer *x509.Certificate, signer *rsa.PrivateKey, revokedSerials []*big.Int, now time.Time) []byte {
	t.Helper()

	entries := make([]x509.RevocationListEntry, 0, len(revokedSerials))
	for _, serial := range revokedSerials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: now.Add(-30 * time.Minute),
		})
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                now.Add(-1 * time.Hour),
		NextUpdate:                now.Add(24 * time.Hour),
		SignatureAlgorithm:        x509.SHA512WithRSA,
		RevokedCertificateEntries: entries,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, issuer, signer)
	require.NoError(t, err)
	return crlDER
}

func pemEncodeCert(certDER []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))
}

func mustRandomBytes(t *testing.T, size int) []byte {
	t.Helper()
	buffer := make([]byte, size)
	_, err := rand.Read(buffer)
	require.NoError(t, err)
	return buffer
}
