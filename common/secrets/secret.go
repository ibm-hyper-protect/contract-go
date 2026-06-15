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
)

// EncryptSecretNative encrypts a secret using native Go cryptography without external dependencies.
//
// This function performs the complete sealed secret encryption workflow using only Go's standard
// crypto packages:
//  1. Generates random AES-256 key and IV
//  2. Encrypts the secret with AES-256-GCM
//  3. Encrypts the AES key with RSA-PKCS1v15
//  4. Creates a JSON envelope with encrypted data and key
//  5. Signs the envelope with RSA-SHA512
//  6. Constructs JWS compact serialization format
//
// The output format is "sealed.<header>.<payload>.<signature>" compatible with IBM Confidential
// Computing contract decryption mechanisms.
//
// Parameters:
//   - secret: The plaintext secret to encrypt
//   - publicKeyPEM: RSA public key for encrypting the AES key (PEM format)
//   - privateKeyPEM: RSA private key for signing the envelope (PEM format)
//   - secretType: Type of secret ("workload" or "env") - determines key IDs in the envelope
//
// Returns:
//   - Sealed secret in JWS format with "sealed." prefix
//   - Error if any encryption step fails
func EncryptSecretNative(secret string, publicKeyPEM, privateKeyPEM []byte, secretType string) (string, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("failed to generate AES key: %w", err)
	}

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	encryptedData, err := encryptWithAESGCMNative([]byte(secret), aesKey, iv)
	if err != nil {
		return "", fmt.Errorf("AES-GCM encryption failed: %w", err)
	}

	pubKey, err := parseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, aesKey)
	if err != nil {
		return "", fmt.Errorf("RSA encryption of AES key failed: %w", err)
	}

	var keyID, verifyKeyID string
	if secretType == "workload" {
		keyID = "workload_decrypt"
		verifyKeyID = "workload_verify"
	} else {
		keyID = "env_decrypt"
		verifyKeyID = "env_verify"
	}

	envelopeJSON, err := createEnvelopeNative(encryptedData, encryptedKey, iv, keyID)
	if err != nil {
		return "", fmt.Errorf("envelope creation failed: %w", err)
	}

	privKey, err := parseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	sealedSecret, err := constructJWSNative(envelopeJSON, privKey, verifyKeyID)
	if err != nil {
		return "", fmt.Errorf("JWS construction failed: %w", err)
	}

	return sealedSecret, nil
}

// encryptWithAESGCMNative encrypts data using AES-256-GCM.
//
// Parameters:
//   - plaintext: Data to encrypt
//   - key: AES-256 key (32 bytes)
//   - iv: Initialization vector (12 bytes for GCM)
//
// Returns:
//   - Encrypted ciphertext with authentication tag
//   - Error if cipher creation or encryption fails
func encryptWithAESGCMNative(plaintext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)
	return ciphertext, nil
}

// parseRSAPublicKeyFromPEM parses an RSA public key from PEM format.
//
// Parameters:
//   - pemBytes: PEM-encoded RSA public key
//
// Returns:
//   - Parsed RSA public key
//   - Error if PEM decoding or parsing fails
func parseRSAPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}

// parseRSAPrivateKeyFromPEM parses an RSA private key from PEM format.
//
// This function supports both PKCS1 and PKCS8 formats, trying PKCS1 first then falling back to PKCS8.
//
// Parameters:
//   - pemBytes: PEM-encoded RSA private key
//
// Returns:
//   - Parsed RSA private key
//   - Error if PEM decoding or parsing fails for both formats
func parseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privKey, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaPriv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}

	return rsaPriv, nil
}

// createEnvelopeNative creates the JSON envelope structure for the sealed secret.
//
// Parameters:
//   - encryptedData: AES-GCM encrypted secret data
//   - encryptedKey: RSA-encrypted AES key
//   - iv: Initialization vector used for AES-GCM
//   - keyID: Key identifier ("workload_decrypt" or "env_decrypt")
//
// Returns:
//   - JSON-encoded envelope
//   - Error if JSON marshaling fails
func createEnvelopeNative(encryptedData, encryptedKey, iv []byte, keyID string) ([]byte, error) {
	env := map[string]interface{}{
		"version":        "0.1.0",
		"type":           "kms",
		"key_id":         keyID,
		"encrypted_key":  base64.StdEncoding.EncodeToString(encryptedKey),
		"encrypted_data": base64.StdEncoding.EncodeToString(encryptedData),
		"wrap_type":      "A256GCM",
		"iv":             base64.StdEncoding.EncodeToString(iv),
		"provider":       "ibm-hpcr-contract",
	}

	return json.Marshal(env)
}

// constructJWSNative constructs JWS compact serialization format with RS512 signing.
//
// This follows the JWS specification (RFC 7515) where the signature is computed over:
// ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload))
//
// Parameters:
//   - envelopeJSON: JSON envelope containing encrypted data and key
//   - privKey: RSA private key for signing
//   - verifyKeyID: Key identifier for verification ("workload_verify" or "env_verify")
//
// Returns:
//   - Sealed secret in format "sealed.<header>.<payload>.<signature>"
//   - Error if signing or encoding fails
func constructJWSNative(envelopeJSON []byte, privKey *rsa.PrivateKey, verifyKeyID string) (string, error) {
	header := map[string]interface{}{
		"alg": "RS512",
		"kid": verifyKeyID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWS header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadB64 := base64.RawURLEncoding.EncodeToString(envelopeJSON)

	signingInput := headerB64 + "." + payloadB64

	hashed := sha512.Sum512([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA512, hashed[:])
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	jws := fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, signatureB64)

	return "sealed." + jws, nil
}

// ExtractPublicKeyFromPrivateNative extracts the RSA public key from a private key.
//
// Parameters:
//   - privateKeyPEM: RSA private key in PEM format
//
// Returns:
//   - RSA public key in PEM format
//   - Error if private key parsing or public key extraction fails
func ExtractPublicKeyFromPrivateNative(privateKeyPEM []byte) ([]byte, error) {
	privKey, err := parseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return publicKeyPEM, nil
}

// GenerateRSAKeyPairNative generates a 2048-bit RSA key pair.
//
// Returns:
//   - RSA public key in PEM format
//   - RSA private key in PEM format (PKCS1)
//   - Error if key generation or encoding fails
func GenerateRSAKeyPairNative() (publicKeyPEM, privateKeyPEM []byte, err error) {
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
