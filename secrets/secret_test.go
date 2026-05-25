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

package secrets

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/ibm-hyper-protect/contract-go/v2/common/general"
	"github.com/stretchr/testify/assert"
)

// TestHpccSealedSecretWorkload tests sealing a workload secret.
func TestHpccSealedSecretWorkload(t *testing.T) {
	sealedSecret, decryptionKey, verificationKey, inputSha, encryptedSha, err := HpccSealedSecret("test-secret", "workload", "", "")
	assert.NoError(t, err, "Failed to seal secret")

	// Verify sealed secret format
	assert.True(t, strings.HasPrefix(sealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify sealed secret has JWS structure (sealed.header.payload.signature)
	parts := strings.Split(sealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Expected 4 parts in sealed secret (sealed.header.payload.signature)")

	// Verify all keys are present
	assert.NotEmpty(t, decryptionKey, "Decryption key is empty")
	assert.NotEmpty(t, verificationKey, "Verification key is empty")

	// Verify keys are in PEM format
	assert.Contains(t, decryptionKey, "BEGIN", "Decryption key not in PEM format")
	assert.Contains(t, verificationKey, "BEGIN PUBLIC KEY", "Verification key not in PEM format")

	// Verify SHA hashes are present
	assert.NotEmpty(t, inputSha, "Input SHA is empty")
	assert.NotEmpty(t, encryptedSha, "Encrypted SHA is empty")
	assert.Equal(t, 64, len(inputSha), "Input SHA should be 64 characters (SHA-256 hex)")
	assert.Equal(t, 64, len(encryptedSha), "Encrypted SHA should be 64 characters (SHA-256 hex)")
}

// TestHpccSealedSecretEnv tests sealing an environment secret.
func TestHpccSealedSecretEnv(t *testing.T) {
	sealedSecret, _, _, _, _, err := HpccSealedSecret("test-secret", "env", "", "")
	assert.NoError(t, err, "Failed to seal secret")

	assert.True(t, strings.HasPrefix(sealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify JWS structure
	parts := strings.Split(sealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Expected 4 parts in sealed secret")
}

// TestHpccSealedSecretEmptySecret tests that empty secrets are rejected.
func TestHpccSealedSecretEmptySecret(t *testing.T) {
	_, _, _, _, _, err := HpccSealedSecret("", "workload", "", "")
	assert.Error(t, err, "Expected error for empty secret")
	assert.Contains(t, err.Error(), "empty", "Expected error message to mention 'empty'")
}

// TestHpccSealedSecretInvalidType tests that invalid secret types are rejected.
func TestHpccSealedSecretInvalidType(t *testing.T) {
	_, _, _, _, _, err := HpccSealedSecret("test", "invalid", "", "")
	assert.Error(t, err, "Expected error for invalid secret type")
	assert.Contains(t, err.Error(), "invalid secret type", "Expected error message to mention 'invalid secret type'")
}

// TestHpccSealedSecretDifferentSecrets tests that different secrets produce different results.
func TestHpccSealedSecretDifferentSecrets(t *testing.T) {
	sealed1, decKey1, _, inputSha1, encSha1, err := HpccSealedSecret("secret1", "workload", "", "")
	assert.NoError(t, err, "Failed to seal first secret")

	sealed2, decKey2, _, inputSha2, encSha2, err := HpccSealedSecret("secret2", "workload", "", "")
	assert.NoError(t, err, "Failed to seal second secret")

	// Sealed secrets should be different
	assert.NotEqual(t, sealed1, sealed2, "Different secrets produced identical sealed secrets")

	// Keys should be different (freshly generated each time)
	assert.NotEqual(t, decKey1, decKey2, "Different calls produced identical decryption keys")

	// Input SHAs should be different
	assert.NotEqual(t, inputSha1, inputSha2, "Different secrets produced identical input SHAs")

	// Encrypted SHAs should be different
	assert.NotEqual(t, encSha1, encSha2, "Different secrets produced identical encrypted SHAs")
}

// TestHpccSealedSecretLongSecret tests sealing a longer secret.
func TestHpccSealedSecretLongSecret(t *testing.T) {
	longSecret := strings.Repeat("This is a long secret. ", 100)
	sealedSecret, _, _, _, _, err := HpccSealedSecret(longSecret, "workload", "", "")
	assert.NoError(t, err, "Failed to seal long secret")
	assert.True(t, strings.HasPrefix(sealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")
}

// TestHpccSealedSecretSpecialCharacters tests sealing secrets with special characters.
func TestHpccSealedSecretSpecialCharacters(t *testing.T) {
	specialSecrets := []string{
		"password!@#$%^&*()",
		"key with spaces",
		"unicode: 你好世界",
		"newlines\nand\ttabs",
		`{"json": "value"}`,
	}

	for _, secret := range specialSecrets {
		t.Run(secret, func(t *testing.T) {
			sealedSecret, _, _, _, _, err := HpccSealedSecret(secret, "workload", "", "")
			assert.NoError(t, err, "Failed to seal secret with special characters")
			assert.True(t, strings.HasPrefix(sealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")
		})
	}
}

// BenchmarkHpccSealedSecret benchmarks the complete seal secret operation.
func BenchmarkHpccSealedSecret(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, err := HpccSealedSecret("benchmark-secret", "workload", "", "")
		assert.NoError(b, err, "Failed to seal secret")
	}
}

// TestDecryptWithGoCrypto demonstrates that sealed secrets created with native Go crypto
// can be decrypted using Go's crypto packages (AES-256-GCM + RSA-OAEP-SHA512).
func TestDecryptWithGoCrypto(t *testing.T) {
	originalSecret := "my-test-password-123"

	// Step 1: Create sealed secret using our package
	sealedSecret, decryptionKeyPEM, _, inputSha, encryptedSha, err := HpccSealedSecret(originalSecret, "workload", "", "")
	assert.NoError(t, err, "Failed to seal secret")

	// Verify input SHA matches
	expectedInputSha := general.GenerateSha256(originalSecret)
	assert.Equal(t, expectedInputSha, inputSha, "Input SHA doesn't match")

	// Verify encrypted SHA matches
	expectedEncryptedSha := general.GenerateSha256(sealedSecret)
	assert.Equal(t, expectedEncryptedSha, encryptedSha, "Encrypted SHA doesn't match")

	// Step 2: Parse the JWS format (sealed.header.payload.signature)
	parts := strings.Split(sealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Invalid sealed secret format")
	assert.Equal(t, "sealed", parts[0], "Invalid sealed secret format")

	// Step 3: Decode the payload (envelope)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	assert.NoError(t, err, "Failed to decode payload")

	// Define envelope structure for decryption
	type envelope struct {
		Version       string `json:"version"`
		Type          string `json:"type"`
		KeyID         string `json:"key_id"`
		EncryptedKey  string `json:"encrypted_key"`
		EncryptedData string `json:"encrypted_data"`
		WrapType      string `json:"wrap_type"`
		IV            string `json:"iv"`
		Provider      string `json:"provider"`
	}

	var env envelope
	err = json.Unmarshal(payloadBytes, &env)
	assert.NoError(t, err, "Failed to unmarshal envelope")

	// Verify it's using GCM
	assert.Equal(t, "A256GCM", env.WrapType, "Expected wrap_type A256GCM")

	// Step 4: Decode the encrypted AES key
	encryptedAESKey, err := base64.StdEncoding.DecodeString(env.EncryptedKey)
	assert.NoError(t, err, "Failed to decode encrypted AES key")

	// Step 5: Parse the RSA private key (decryption key)
	block, _ := pem.Decode([]byte(decryptionKeyPEM))
	assert.NotNil(t, block, "Failed to parse PEM block")

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		assert.NoError(t, err, "Failed to parse private key")
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	assert.True(t, ok, "Not an RSA private key")

	// Step 6: Decrypt the AES key using RSA PKCS#1 v1.5 (same as agent-interceptor)
	aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, encryptedAESKey)
	assert.NoError(t, err, "Failed to decrypt AES key")

	// Step 7: Decode the encrypted data and IV
	encryptedData, err := base64.StdEncoding.DecodeString(env.EncryptedData)
	assert.NoError(t, err, "Failed to decode encrypted data")

	iv, err := base64.StdEncoding.DecodeString(env.IV)
	assert.NoError(t, err, "Failed to decode IV")

	// Step 8: Decrypt the data using AES-256-GCM (Go crypto)
	block2, err := aes.NewCipher(aesKey)
	assert.NoError(t, err, "Failed to create AES cipher")

	gcm, err := cipher.NewGCM(block2)
	assert.NoError(t, err, "Failed to create GCM")

	// GCM decrypt (nonce is the IV, ciphertext includes auth tag)
	decryptedData, err := gcm.Open(nil, iv, encryptedData, nil)
	assert.NoError(t, err, "Failed to decrypt data with GCM")

	decryptedSecret := string(decryptedData)

	// Step 9: Verify the decrypted secret matches the original
	assert.Equal(t, originalSecret, decryptedSecret, "Decrypted secret doesn't match original")
}

// TestVerifySignatureWithGoCrypto demonstrates signature verification using Go crypto.
func TestVerifySignatureWithGoCrypto(t *testing.T) {
	// Step 1: Create sealed secret
	sealedSecret, _, verificationKeyPEM, _, _, err := HpccSealedSecret("test-secret", "workload", "", "")
	assert.NoError(t, err, "Failed to seal secret")

	// Step 2: Parse JWS (format: sealed.header.payload.signature)
	parts := strings.Split(sealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Invalid JWS format")

	// Step 3: Get the signature
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	assert.NoError(t, err, "Failed to decode signature")

	// Step 4: Parse the verification key (RSA public key)
	block, _ := pem.Decode([]byte(verificationKeyPEM))
	assert.NotNil(t, block, "Failed to parse PEM block")

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "Failed to parse public key")

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	assert.True(t, ok, "Not an RSA public key")

	// Step 5: Construct the signing input (header.payload)
	// Per JWS spec, signature is computed over: BASE64URL(header) || '.' || BASE64URL(payload)
	signingInput := parts[1] + "." + parts[2]

	// Step 6: Verify the signature using Go crypto (RSA-SHA512)
	hashed := sha512.Sum512([]byte(signingInput))
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA512, hashed[:], signatureBytes)
	assert.NoError(t, err, "Signature verification failed")
}

// TestHpccSealedSecretWithProvidedKeys tests sealing with user-provided encryption and signing keys as strings.
func TestHpccSealedSecretWithProvidedKeys(t *testing.T) {
	// Generate keys to use
	_, encPrivKey, err := generateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate encryption key pair")

	_, signPrivKey, err := generateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate signing key pair")

	// Seal secret with provided key strings
	sealedSecret, decryptionKey, _, _, _, err := HpccSealedSecret("test-secret", "workload", string(encPrivKey), string(signPrivKey))
	assert.NoError(t, err, "Failed to seal secret with provided keys")

	// Verify sealed secret format
	assert.True(t, strings.HasPrefix(sealedSecret, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify the returned keys match what we provided
	assert.Equal(t, string(encPrivKey), decryptionKey, "Returned decryption key doesn't match provided encryption key")

	// Verify the sealed secret is not empty and has correct format
	parts := strings.Split(sealedSecret, ".")
	assert.Equal(t, 4, len(parts), "Expected 4 parts in sealed secret")
}

// TestHpccSealedSecretWithPartialKeys tests that providing only one key generates the other.
func TestHpccSealedSecretWithPartialKeys(t *testing.T) {
	// Generate only encryption key
	_, encPrivKey, err := generateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate encryption key pair")

	// Seal with only encryption key provided (signing key should be generated)
	sealed1, decKey1, verKey1, _, _, err := HpccSealedSecret("test-secret", "workload", string(encPrivKey), "")
	assert.NoError(t, err, "Failed to seal secret with partial keys")

	// Verify sealed secret was created
	assert.True(t, strings.HasPrefix(sealed1, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify encryption key matches what we provided
	assert.Equal(t, string(encPrivKey), decKey1, "Returned decryption key doesn't match provided encryption key")

	// Verify signing key was generated (should not be empty)
	assert.NotEmpty(t, verKey1, "Verification key should have been generated but is empty")

	// Generate only signing key
	_, signPrivKey, err := generateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate signing key pair")

	// Seal with only signing key provided (encryption key should be generated)
	sealed2, decKey2, _, _, _, err := HpccSealedSecret("test-secret", "env", "", string(signPrivKey))
	assert.NoError(t, err, "Failed to seal secret with partial keys")

	// Verify sealed secret was created
	assert.True(t, strings.HasPrefix(sealed2, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify encryption key was generated (should not be empty)
	assert.NotEmpty(t, decKey2, "Decryption key should have been generated but is empty")
}

// Helper function to generate RSA key pair for testing
func generateRSAKeyPairNative() (publicKeyPEM, privateKeyPEM []byte, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return publicKeyPEM, privateKeyPEM, nil
}
