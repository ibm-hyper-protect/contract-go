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
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRSAKeyPairNative(t *testing.T) {
	pubKey, privKey, err := GenerateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate RSA key pair")

	assert.NotEmpty(t, pubKey, "Public key is empty")
	assert.NotEmpty(t, privKey, "Private key is empty")

	// Check PEM format
	assert.Contains(t, string(pubKey), "BEGIN PUBLIC KEY", "Public key not in PEM format")
	assert.Contains(t, string(privKey), "BEGIN RSA PRIVATE KEY", "Private key not in PEM format")
}

func TestEncryptSecretNative(t *testing.T) {
	// Generate keys
	encPubKey, _, err := GenerateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate encryption keys")

	_, signPrivKey, err := GenerateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate signing keys")

	// Encrypt a secret
	secret := "test-secret-password"
	sealed, err := EncryptSecretNative(secret, encPubKey, signPrivKey, "workload")
	assert.NoError(t, err, "Failed to encrypt secret")

	// Verify format
	assert.True(t, strings.HasPrefix(sealed, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify JWS structure (sealed.header.payload.signature)
	parts := strings.Split(sealed, ".")
	assert.Equal(t, 4, len(parts), "Expected 4 parts in sealed secret")
}

func TestEncryptWithProvidedKeysNative(t *testing.T) {
	// Your provided keys
	decryptionKey := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC06q3Joxn75PEw
T1fSHr2mouEcXS/3tn0R6obh5nqMEKb5j+a6H9hqQmPogKGWupZbWDFv9/6EFqez
rgtWDeRa4l9gNBt5ykypUBZjjeZNG8oMp7VliOexXyqrIV+3xYypZzHSs3zegv72
LKtAmuzCmAPYMRrGRXcb4ivPRErGFsgXiVGSpswAjnoitofsXWtKP8LJWPsP9Ooq
2zQfOLKjm1h3Yq9+FR8liscSwc9o2TdGNKg2Q7K6lkKJR4UEPKJ9RADU8zfs09KA
/vr1XvOGJ52xWgzEjJgb89ZJIiH0ww8x0laTqd4pY4gR4yaI0Itd2MOfClsyBFal
rQ9m5J65AgMBAAECggEAAjnF4A5p3iuznObI+4yFxERKNS1fTvKXiM4kESji9pCo
4TaYPc9w++Ors3tLoZ1ThrWnzAsWvjzCHOeF+63JkqWoyzfw45dtyIJz+A8Rl37B
RlUU2fYsdYXocjkDorDjOV1L413yahFd/hzQEYgmZAF3QKRgAjLuE3F9nPvn2JZ/
XIcrEtw5f8HVbUxIP79c4x/9Cm+/ZcnC6EtZMvOGAeO3tuSL1ZQ/rO/K+t+hqVvF
n4VjPfZC9Js2QuiTppZ3MjQ/E2BdSYTtheh2QTnl0nblxvttdX6s0id+oBFHrtHp
6J0PGSP/z0MTiEi1llc7oQb3hZzwCg3R8jQgzNPUYQKBgQDf/wlm3I2nZa61Tti3
j7+QVO3cbaWcnStU7O85oWukVT7IyLeogQiSMq8cSNyUu7NjlPbl6M+GKYHcnegK
3jC4lpehdUzJSdg49VlYRBUtqxLfyZlyhyILVsGFn0wo1HlooWelTL1Q/NkQNi/m
x2vK2PP5s3YUME881Y3zAvKasQKBgQDOw/Nh2fZrVpTGnI06e7KwfnLKM8KpnBgH
Dg3L4TF8CWNvLk63QFY2rutAhovByLazc1JQcLKDc0JSWo5fL8X4IrPneJgr1fSu
KDBW+9tXFdTsTSJ/HdwfHxzz2UF0DcLzKDOJIHkmIqeWJXJbcW+OqlSeja+JIfr0
fzW7o/a2iQKBgQCc8BZJQEvrNf3jQBvs+EUyPZ7t6tC22xOKC/tMOIGvgJ5dlOvA
nq8/p00zFwWdG6mDItKdoLENgbVfui7itmwSWEhiskmbWiapOZVgl0rzVUIDEz90
k6NRqHYsRcDZdoydt0Bj+1FFFfKLPjvviFdIpxrBH3Ciknph2An9clpB8QKBgGvZ
ObHohugmGSQftGq06te0nRtrNDZT/RRw+DFIHQ+dtgfgF57uKAoN4xedFnjVwLaJ
iH38yqBWFlnuciSkPpbXQw+Rj44N47qTq+MzK42ZDZ7T/RJg+Ngi2m82+zUVmIJM
jdUQ4yBJIzDmB2g7Gv1HSywIq27UEppFYDmnpKBBAoGBANimfhp4T7aUtpQCG1cT
0HshnjfMXY70o1yi9oOI9c3UChIE0wN+AVXh5jPvb2LjSgc463aGmqMYl1CKhBvT
ECOyx/rCAYJjNK7FShli71VB9Kpd/1QW9Lk4nLrEhIh+9Hd3qlboxEHLOyfnYdmm
xtFuPG58m22czKDvYDqLuM4I
-----END PRIVATE KEY-----`)

	// Generate encryption public key
	encPubKey, _, err := GenerateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate keys")

	// Encrypt with provided keys
	secret := "test-password"
	sealed, err := EncryptSecretNative(secret, encPubKey, decryptionKey, "workload")
	assert.NoError(t, err, "Failed to encrypt with provided keys")

	// Verify format
	assert.True(t, strings.HasPrefix(sealed, "sealed."), "Sealed secret doesn't have 'sealed.' prefix")

	// Verify JWS structure
	parts := strings.Split(sealed, ".")
	assert.Equal(t, 4, len(parts), "Expected 4 parts in sealed secret")
}

// TestExtractPublicKeyFromPrivateNative tests extracting public key from private key
func TestExtractPublicKeyFromPrivateNative(t *testing.T) {
	// Generate a key pair
	pubKey, privKey, err := GenerateRSAKeyPairNative()
	assert.NoError(t, err, "Failed to generate key pair")

	// Extract public key from private key
	extractedPubKey, err := ExtractPublicKeyFromPrivateNative(privKey)
	assert.NoError(t, err, "Failed to extract public key")

	// Verify the extracted public key matches the original
	assert.Equal(t, string(pubKey), string(extractedPubKey), "Extracted public key doesn't match original public key")

	// Verify the extracted key is valid PEM
	block, _ := pem.Decode(extractedPubKey)
	assert.NotNil(t, block, "Failed to decode extracted public key PEM")
	assert.Equal(t, "PUBLIC KEY", block.Type, "Expected PUBLIC KEY block type")

	// Verify we can parse it as a public key
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	assert.NoError(t, err, "Failed to parse extracted public key")
}

// TestExtractPublicKeyFromPrivateNative_InvalidKey tests error handling
func TestExtractPublicKeyFromPrivateNative_InvalidKey(t *testing.T) {
	tests := []struct {
		name    string
		privKey []byte
		wantErr bool
	}{
		{
			name:    "empty key",
			privKey: []byte{},
			wantErr: true,
		},
		{
			name:    "invalid PEM",
			privKey: []byte("not a valid PEM"),
			wantErr: true,
		},
		{
			name: "invalid key data",
			privKey: []byte(`-----BEGIN RSA PRIVATE KEY-----
invalid data here
-----END RSA PRIVATE KEY-----`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractPublicKeyFromPrivateNative(tt.privKey)
			if tt.wantErr {
				assert.Error(t, err, "ExtractPublicKeyFromPrivateNative() should return error")
			} else {
				assert.NoError(t, err, "ExtractPublicKeyFromPrivateNative() should not return error")
			}
		})
	}
}
