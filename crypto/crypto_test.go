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

package crypto

import (
	"strings"
	"testing"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// GenerateOpenSSLArtifacts — key type
// ---------------------------------------------------------------------------

// TestGenerateOpenSSLArtifacts_Key verifies that a 2048-bit unencrypted key pair
// is produced: both PEM fields and their SHA-256 hashes are non-empty; cert
// fields and their hashes are all empty.
func TestGenerateOpenSSLArtifacts_Key(t *testing.T) {
	privKey, pubKey, caCert, clientCert, clientKey,
		privKeySha, pubKeySha, caCertSha, clientCertSha, clientKeySha,
		err := GenerateOpenSSLArtifacts("key", "", "", "", 2048, 0)
	assert.NoError(t, err)

	assert.NotEmpty(t, privKey)
	assert.NotEmpty(t, pubKey)

	// OpenSSL 3.x genrsa outputs PKCS#8 ("PRIVATE KEY"), not PKCS#1 ("RSA PRIVATE KEY")
	assert.Contains(t, privKey, "PRIVATE KEY")
	assert.Contains(t, pubKey, "PUBLIC KEY")

	// SHA-256 hashes must be non-empty and match the PEM values
	assert.NotEmpty(t, privKeySha)
	assert.NotEmpty(t, pubKeySha)
	assert.Equal(t, gen.GenerateSha256(privKey), privKeySha)
	assert.Equal(t, gen.GenerateSha256(pubKey), pubKeySha)

	// cert fields and their hashes must be empty for --type key
	assert.Empty(t, caCert)
	assert.Empty(t, clientCert)
	assert.Empty(t, clientKey)
	assert.Empty(t, caCertSha)
	assert.Empty(t, clientCertSha)
	assert.Empty(t, clientKeySha)
}

// TestGenerateOpenSSLArtifacts_Key4096 verifies a 4096-bit key pair.
func TestGenerateOpenSSLArtifacts_Key4096(t *testing.T) {
	privKey, pubKey, _, _, _, privKeySha, pubKeySha, _, _, _, err :=
		GenerateOpenSSLArtifacts("key", "", "", "", 4096, 0)
	assert.NoError(t, err)
	assert.NotEmpty(t, privKey)
	assert.NotEmpty(t, pubKey)
	assert.NotEmpty(t, privKeySha)
	assert.NotEmpty(t, pubKeySha)
}

// TestGenerateOpenSSLArtifacts_KeyWithPassword verifies that when a password is
// provided the private key PEM is encrypted and still has a valid SHA.
func TestGenerateOpenSSLArtifacts_KeyWithPassword(t *testing.T) {
	privKey, pubKey, _, _, _, privKeySha, pubKeySha, _, _, _, err :=
		GenerateOpenSSLArtifacts("key", "test-passphrase-123", "", "", 2048, 0)
	assert.NoError(t, err)
	assert.NotEmpty(t, privKey)
	assert.NotEmpty(t, pubKey)

	// openssl rsa -aes256 produces an ENCRYPTED header
	assert.True(t, gen.IsPrivateKeyEncrypted(privKey),
		"expected private key to be encrypted when password is provided")

	assert.NotEmpty(t, privKeySha)
	assert.NotEmpty(t, pubKeySha)
}

// ---------------------------------------------------------------------------
// GenerateOpenSSLArtifacts — cert type
// ---------------------------------------------------------------------------

// TestGenerateOpenSSLArtifacts_Cert verifies a basic cert bundle: CA cert,
// client cert, and client key are all populated with their SHA-256 hashes;
// key fields and their hashes are all empty.
func TestGenerateOpenSSLArtifacts_Cert(t *testing.T) {
	privKey, pubKey, caCert, clientCert, clientKey,
		privKeySha, pubKeySha, caCertSha, clientCertSha, clientKeySha,
		err := GenerateOpenSSLArtifacts("cert", "", "example.com", "example.com", 2048, 365)
	assert.NoError(t, err)

	assert.NotEmpty(t, caCert)
	assert.NotEmpty(t, clientCert)
	assert.NotEmpty(t, clientKey)

	assert.Contains(t, caCert, "BEGIN CERTIFICATE")
	assert.Contains(t, clientCert, "BEGIN CERTIFICATE")
	// OpenSSL 3.x genrsa outputs PKCS#8 ("PRIVATE KEY"), not PKCS#1 ("RSA PRIVATE KEY")
	assert.Contains(t, clientKey, "PRIVATE KEY")

	// SHA-256 hashes must be non-empty and match the PEM values
	assert.NotEmpty(t, caCertSha)
	assert.NotEmpty(t, clientCertSha)
	assert.NotEmpty(t, clientKeySha)
	assert.Equal(t, gen.GenerateSha256(caCert), caCertSha)
	assert.Equal(t, gen.GenerateSha256(clientCert), clientCertSha)
	assert.Equal(t, gen.GenerateSha256(clientKey), clientKeySha)

	// key fields and their hashes must be empty for --type cert
	assert.Empty(t, privKey)
	assert.Empty(t, pubKey)
	assert.Empty(t, privKeySha)
	assert.Empty(t, pubKeySha)
}

// TestGenerateOpenSSLArtifacts_CertWithPassword verifies that when a password
// is provided the client private key is encrypted and still has a valid SHA.
func TestGenerateOpenSSLArtifacts_CertWithPassword(t *testing.T) {
	_, _, _, _, clientKey, _, _, _, _, clientKeySha, err :=
		GenerateOpenSSLArtifacts("cert", "cert-pass-456", "secure.example.com", "secure.example.com", 2048, 365)
	assert.NoError(t, err)
	assert.NotEmpty(t, clientKey)

	assert.True(t, gen.IsPrivateKeyEncrypted(clientKey),
		"expected client key to be encrypted when password is provided")

	assert.NotEmpty(t, clientKeySha)
}

// TestGenerateOpenSSLArtifacts_CertMultiSAN verifies a cert with multiple
// SANs including both DNS names and an IP address.
func TestGenerateOpenSSLArtifacts_CertMultiSAN(t *testing.T) {
	_, _, _, clientCert, _, _, _, _, clientCertSha, _, err :=
		GenerateOpenSSLArtifacts("cert", "", "example.com", "example.com,www.example.com,192.168.1.1", 2048, 365)
	assert.NoError(t, err)
	assert.NotEmpty(t, clientCert)
	assert.NotEmpty(t, clientCertSha)
}

// TestGenerateOpenSSLArtifacts_CertIPOnlySAN verifies a cert whose only SAN
// is an IP address.
func TestGenerateOpenSSLArtifacts_CertIPOnlySAN(t *testing.T) {
	_, _, _, clientCert, _, _, _, _, clientCertSha, _, err :=
		GenerateOpenSSLArtifacts("cert", "", "127.0.0.1", "127.0.0.1", 2048, 365)
	assert.NoError(t, err)
	assert.NotEmpty(t, clientCert)
	assert.NotEmpty(t, clientCertSha)
}

// TestGenerateOpenSSLArtifacts_CertDefaultSAN verifies that the caller-applied
// default SAN value "example.com" works correctly.
func TestGenerateOpenSSLArtifacts_CertDefaultSAN(t *testing.T) {
	_, _, caCert, clientCert, clientKey, _, _, caCertSha, clientCertSha, clientKeySha, err :=
		GenerateOpenSSLArtifacts("cert", "", "example.com", "example.com", 2048, 365)
	assert.NoError(t, err)
	assert.NotEmpty(t, caCert)
	assert.NotEmpty(t, clientCert)
	assert.NotEmpty(t, clientKey)
	assert.NotEmpty(t, caCertSha)
	assert.NotEmpty(t, clientCertSha)
	assert.NotEmpty(t, clientKeySha)
}

// ---------------------------------------------------------------------------
// GenerateOpenSSLArtifacts — invalid inputs
// ---------------------------------------------------------------------------

// TestGenerateOpenSSLArtifacts_InvalidType verifies error on bad type.
func TestGenerateOpenSSLArtifacts_InvalidType(t *testing.T) {
	_, _, _, _, _, _, _, _, _, _, err := GenerateOpenSSLArtifacts("other", "", "", "", 2048, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid type")
}

// TestGenerateOpenSSLArtifacts_InvalidSize verifies error on bad key size.
func TestGenerateOpenSSLArtifacts_InvalidSize(t *testing.T) {
	_, _, _, _, _, _, _, _, _, _, err := GenerateOpenSSLArtifacts("key", "", "", "", 1024, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

// TestGenerateOpenSSLArtifacts_ValidSizes verifies that all accepted key sizes pass.
func TestGenerateOpenSSLArtifacts_ValidSizes(t *testing.T) {
	for _, size := range []int{2048, 3072, 4096} {
		_, _, _, _, _, _, _, _, _, _, err := GenerateOpenSSLArtifacts("key", "", "", "", size, 0)
		assert.NoError(t, err, "expected no error for key size %d", size)
	}
}

// TestGenerateOpenSSLArtifacts_DifferentCallsProduceDifferentKeys verifies
// that two calls generate independent key material and therefore different SHAs.
func TestGenerateOpenSSLArtifacts_DifferentCallsProduceDifferentKeys(t *testing.T) {
	priv1, pub1, _, _, _, privSha1, pubSha1, _, _, _, err := GenerateOpenSSLArtifacts("key", "", "", "", 2048, 0)
	assert.NoError(t, err)

	priv2, pub2, _, _, _, privSha2, pubSha2, _, _, _, err := GenerateOpenSSLArtifacts("key", "", "", "", 2048, 0)
	assert.NoError(t, err)

	assert.NotEqual(t, priv1, priv2, "two independent calls must produce different private keys")
	assert.NotEqual(t, pub1, pub2, "two independent calls must produce different public keys")
	assert.NotEqual(t, privSha1, privSha2, "different private keys must have different SHAs")
	assert.NotEqual(t, pubSha1, pubSha2, "different public keys must have different SHAs")
}

// TestGenerateOpenSSLArtifacts_CACertIsSelfSigned verifies the CA cert PEM
// header and that it differs from the client cert (and therefore its SHA too).
func TestGenerateOpenSSLArtifacts_CACertIsSelfSigned(t *testing.T) {
	_, _, caCert, clientCert, _, _, _, caCertSha, clientCertSha, _, err :=
		GenerateOpenSSLArtifacts("cert", "", "example.com", "example.com", 2048, 365)
	assert.NoError(t, err)

	assert.True(t, strings.HasPrefix(strings.TrimSpace(caCert), "-----BEGIN CERTIFICATE-----"),
		"CA cert must start with CERTIFICATE PEM header")
	assert.NotEqual(t, caCert, clientCert, "CA cert and client cert must be different")
	assert.NotEqual(t, caCertSha, clientCertSha, "CA cert SHA and client cert SHA must be different")
}

// ---------------------------------------------------------------------------
// buildSANExt
// ---------------------------------------------------------------------------

// TestBuildSANExt_DNSOnly verifies that DNS names receive the DNS: prefix.
func TestBuildSANExt_DNSOnly(t *testing.T) {
	result := buildSANExt("example.com")
	assert.Equal(t, "DNS:example.com", result)
}

// TestBuildSANExt_IPOnly verifies that IP addresses receive the IP: prefix.
func TestBuildSANExt_IPOnly(t *testing.T) {
	result := buildSANExt("127.0.0.1")
	assert.Equal(t, "IP:127.0.0.1", result)
}

// TestBuildSANExt_Mixed verifies mixed DNS + IP SAN entries.
func TestBuildSANExt_Mixed(t *testing.T) {
	result := buildSANExt("example.com,127.0.0.1,*.internal")
	assert.Equal(t, "DNS:example.com,IP:127.0.0.1,DNS:*.internal", result)
}

// TestBuildSANExt_Whitespace verifies that surrounding whitespace is trimmed.
func TestBuildSANExt_Whitespace(t *testing.T) {
	result := buildSANExt(" example.com , 192.168.1.1 ")
	assert.Equal(t, "DNS:example.com,IP:192.168.1.1", result)
}

// TestBuildSANExt_IPv6 verifies that IPv6 addresses receive the IP: prefix.
func TestBuildSANExt_IPv6(t *testing.T) {
	result := buildSANExt("::1")
	assert.Equal(t, "IP:::1", result)
}
