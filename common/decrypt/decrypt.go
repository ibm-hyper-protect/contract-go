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

	enc "github.com/ibm-hyper-protect/contract-go/common/encrypt"
	gen "github.com/ibm-hyper-protect/contract-go/common/general"
)

// DecryptPassword - function to decrypt encrypted string with private key
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

	result, err := gen.ExecCommand("", "pkeyutl", "-decrypt", "-inkey", privateKeyPath, "-in", encryptedDataPath)
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

// DecryptWorkload - function to decrypt workload using password
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

	result, err := gen.ExecCommand(password, "aes-256-cbc", "-d", "-pbkdf2", "-in", encryptedDataPath, "-pass", "stdin")
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	err = gen.RemoveTempFile(encryptedDataPath)
	if err != nil {
		return "", fmt.Errorf("failed to remove temp file - %v", err)
	}

	return result, nil
}
