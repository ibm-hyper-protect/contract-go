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
	"strings"

	enc "github.com/ibm-hyper-protect/contract-go/v3/common/encrypt"
	gen "github.com/ibm-hyper-protect/contract-go/v3/common/general"
)

// DecryptPassword decrypts an encrypted password using an RSA private key.
// It decodes the Base64-encoded encrypted data, creates temporary files for processing,
// and uses OpenSSL to perform RSA decryption with the private key.
//
// Parameters:
//   - base64EncryptedData: Base64-encoded encrypted password
//   - privateKey: RSA private key (PEM format) for decryption
//   - password: Optional password to unlock the private key (empty string "" for unencrypted keys)
//
// Returns:
//   - Decrypted password string
//   - Error if OpenSSL is not found, Base64 decoding fails, or decryption fails
func DecryptPassword(base64EncryptedData, privateKey, password string) (string, error) {
	err := enc.OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	if gen.IsPrivateKeyEncrypted(privateKey) && password == "" {
		return "", fmt.Errorf("private key is encrypted but no password provided - use the password parameter to unlock the key")
	}

	decodedEncryptedData, err := gen.DecodeBase64String(base64EncryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode Base64 - %v", err)
	}

	encryptedDataPath, err := gen.CreateTempBinaryFile([]byte(decodedEncryptedData))
	if err != nil {
		return "", fmt.Errorf("failed to generate temp file - %v", err)
	}
	defer gen.RemoveTempFile(encryptedDataPath)

	privateKeyPath, err := gen.CreateTempFile(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}
	defer gen.RemoveTempFile(privateKeyPath)

	args := []string{"pkeyutl", "-decrypt", "-inkey", privateKeyPath}
	args = gen.AppendPasswordFdArgs(args, password)
	args = append(args, "-in", encryptedDataPath)

	result, err := gen.ExecCommandWithPassword(gen.GetOpenSSLPath(), "", password, args...)
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	return result, nil
}

// DecryptWorkload decrypts encrypted workload data using a password.
// It decodes the Base64-encoded encrypted workload, creates a temporary file,
// and uses OpenSSL with AES-256-CBC and PBKDF2 to decrypt the data.
//
// Parameters:
//   - password: Password for AES-256-CBC decryption
//   - encryptedWorkload: Base64-encoded encrypted workload data
//
// Returns:
//   - Decrypted workload string
//   - Error if OpenSSL is not found, Base64 decoding fails, or decryption fails
func DecryptWorkload(password, encryptedWorkload string) (string, error) {
	err := enc.OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	decodedEncryptedWorkload, err := gen.DecodeBase64String(encryptedWorkload)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 data - %v", err)
	}

	encryptedDataPath, err := gen.CreateTempBinaryFile([]byte(decodedEncryptedWorkload))
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}
	defer gen.RemoveTempFile(encryptedDataPath)

	args := []string{"aes-256-cbc", "-d", "-pbkdf2", "-in", encryptedDataPath, "-pass", "stdin"}
	// Salted__ has no salt-length field. For AES-CBC its block-aligned
	// ciphertext distinguishes an 8-byte salt from a 16-byte salt. The latter
	// needs an explicit override on OpenSSL versions whose default is 8.
	if strings.HasPrefix(decodedEncryptedWorkload, "Salted__") && len(decodedEncryptedWorkload) >= 40 && (len(decodedEncryptedWorkload)-24)%16 == 0 {
		args = append(args, "-saltlen", "16")
	}
	result, err := gen.ExecCommand(gen.GetOpenSSLPath(), password, args...)
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	return result, nil
}

// DecryptText decrypts encrypted data in contract-basic.<encrypted-password>.<encrypted-data>
//
// Parameters:
//   - data: contract-basic.<encrypted-password>.<encrypted-data>
//   - privateKey: Private key to decrypt the data
//   - password: Optional password to unlock the private key (empty string "" for unencrypted keys)
//
// Returns:
//   - Decrypted data
//   - Error if OpenSSL is not found, Base64 decoding fails, or decryption fails
func DecryptText(data, privateKey, password string) (string, error) {
	encodedEncryptedPassword, encodedEncryptedData, err := gen.GetEncryptPassWorkload(data)
	if err != nil {
		return "", fmt.Errorf("failed to parse encrypted data - %v", err)
	}

	pass, err := DecryptPassword(encodedEncryptedPassword, privateKey, password)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password - %v", err)
	}

	decryptedData, err := DecryptWorkload(pass, encodedEncryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt text - %v", err)
	}

	return decryptedData, nil
}
