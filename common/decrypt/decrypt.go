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

	enc "github.com/ibm-hyper-protect/contract-go/v2/common/encrypt"
	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

// DecryptPassword decrypts an encrypted password using an RSA private key.
// It decodes the Base64-encoded encrypted data, creates temporary files for processing,
// and uses OpenSSL to perform RSA decryption with the private key.
//
// Parameters:
//   - base64EncryptedData: Base64-encoded encrypted password
//   - privateKey: RSA private key (PEM format) for decryption
//
// Returns:
//   - Decrypted password string
//   - Error if OpenSSL is not found, Base64 decoding fails, or decryption fails
func DecryptPassword(base64EncryptedData, privateKey string) (string, error) {
	err := enc.OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	decodedEncryptedData, err := gen.DecodeBase64String(base64EncryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode Base64 - %v", err)
	}

	encryptedDataPath, err := gen.CreateTempFile(decodedEncryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to generate temp file - %v", err)
	}

	privateKeyPath, err := gen.CreateTempFile(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}

	result, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "pkeyutl", "-decrypt", "-inkey", privateKeyPath, "-in", encryptedDataPath)
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	for _, path := range []string{encryptedDataPath, privateKeyPath} {
		err := gen.RemoveTempFile(path)
		if err != nil {
			return "", fmt.Errorf("failed to remove tmp file - %v", err)
		}
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

	encryptedDataPath, err := gen.CreateTempFile(decodedEncryptedWorkload)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}

	result, err := gen.ExecCommand(gen.GetOpenSSLPath(), password, "aes-256-cbc", "-d", "-pbkdf2", "-in", encryptedDataPath, "-pass", "stdin")
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	err = gen.RemoveTempFile(encryptedDataPath)
	if err != nil {
		return "", fmt.Errorf("failed to remove temp file - %v", err)
	}

	return result, nil
}

// DecryptText decrypts encrypted data in hyper-protect-basic.<encrypted-password>.<encrypted-data>
//
// Parameters:
//   - data: hyper-protect-basic.<encrypted-password>.<encrypted-data>
//   - privateKey: Private key to decrypt the data
//
// Returns:
//   - Decrypted data
//   - Error if OpenSSL is not found, Base64 decoding fails, or decryption fails
func DecryptText(data, privateKey string) (string, error) {
	encodedEncryptedPassword, encodedEncryptedData := gen.GetEncryptPassWorkload(data)

	password, err := DecryptPassword(encodedEncryptedPassword, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password - %v", err)
	}

	decryptedData, err := DecryptWorkload(password, encodedEncryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt attestation records - %v", err)
	}

	return decryptedData, nil
}
