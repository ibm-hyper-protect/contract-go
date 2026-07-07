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
	"fmt"

	"github.com/ibm-hyper-protect/contract-go/v2/common/general"
	csecrets "github.com/ibm-hyper-protect/contract-go/v2/common/secrets"
)

// HpccSealedSecret encrypts a secret using AES-256-GCM with RSA key wrapping and RSA-SHA512 signing.
//
// Use this function to create sealed secrets for IBM Confidential Computing workload or environment
// configurations. The function performs the complete encryption workflow: generates or uses provided
// RSA key pairs (as PEM strings or generates new ones), encrypts the secret with AES-256-GCM,
// wraps the AES key with RSA, and signs the result with RSA-SHA512. The output is in JWS compact
// serialization format compatible with IBM Confidential Computing contracts.
//
// Parameters:
//   - secret: The plaintext secret to encrypt (must not be empty)
//   - secretType: Either "workload" or "env", determines key IDs used in the sealed secret
//   - encryptionKey: Optional RSA private key in PEM format string for encryption. If empty, generates new key.
//   - signingKey: Optional RSA private key in PEM format string for signing. If empty, generates new key.
//
// Returns:
//   - sealedSecret: The encrypted secret in JWS format (sealed.<header>.<payload>.<signature>)
//   - decryptionKey: RSA private key for decryption (PEM format string) - store securely
//   - verificationKey: RSA public key for signature verification (PEM format string)
//   - inputSecretSha: SHA-256 hash of the input plaintext secret
//   - encryptedSecretSha: SHA-256 hash of the sealed secret (output)
//   - Error if encryption fails, keys cannot be parsed/generated, or inputs are invalid
func HpccSealedSecret(secret, secretType, encryptionKey, signingKey string) (string, string, string, string, string, error) {
	var err error
	if secret == "" {
		return "", "", "", "", "", fmt.Errorf("secret cannot be empty")
	}

	if secretType != "workload" && secretType != "env" {
		return "", "", "", "", "", fmt.Errorf("invalid secret type: must be 'workload' or 'env'")
	}

	var encPubKey, encPrivKey, signPubKey, signPrivKey []byte

	// Handle encryption key - use provided string or generate new
	if encryptionKey != "" {
		encPrivKey = []byte(encryptionKey)
		encPubKey, err = csecrets.ExtractPublicKeyFromPrivateNative(encPrivKey)
		if err != nil {
			return "", "", "", "", "", fmt.Errorf("failed to extract public key from encryption private key: %w", err)
		}
	} else {
		encPubKey, encPrivKey, err = csecrets.GenerateRSAKeyPairNative()
		if err != nil {
			return "", "", "", "", "", fmt.Errorf("failed to generate encryption key pair: %w", err)
		}
	}

	// Handle signing key - use provided string or generate new
	if signingKey != "" {
		signPrivKey = []byte(signingKey)
		signPubKey, err = csecrets.ExtractPublicKeyFromPrivateNative(signPrivKey)
		if err != nil {
			return "", "", "", "", "", fmt.Errorf("failed to extract public key from signing private key: %w", err)
		}
	} else {
		signPubKey, signPrivKey, err = csecrets.GenerateRSAKeyPairNative()
		if err != nil {
			return "", "", "", "", "", fmt.Errorf("failed to generate signing key pair: %w", err)
		}
	}

	// Encrypt the secret
	sealed, err := csecrets.EncryptSecretNative(secret, encPubKey, signPrivKey, secretType)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Generate SHA-256 hashes
	inputSha := general.GenerateSha256(secret)
	encryptedSha := general.GenerateSha256(sealed)

	return sealed, string(encPrivKey), string(signPubKey), inputSha, encryptedSha, nil
}
