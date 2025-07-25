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

package encrypt

import (
	"encoding/json"
	"fmt"

	gen "github.com/ibm-hyper-protect/contract-go/common/general"
)

const (
	keylen = 32
)

// OpensslCheck - function to check if openssl exists
func OpensslCheck() error {
	_, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "version")

	if err != nil {
		return err
	}

	return nil
}

// GeneratePublicKey - function to generate public key from private key
func GeneratePublicKey(privateKey string) (string, error) {
	err := OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	privateKeyPath, err := gen.CreateTempFile(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}

	publicKey, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "rsa", "-in", privateKeyPath, "-pubout")
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	return publicKey, nil
}

// RandomPasswordGenerator - function to generate random password
func RandomPasswordGenerator() (string, error) {
	err := OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	randomPassword, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "rand", fmt.Sprint(keylen))
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	return randomPassword, nil
}

// EncryptPassword - function to encrypt password
func EncryptPassword(password, cert string) (string, error) {
	err := OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	encryptCertPath, err := gen.CreateTempFile(cert)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}

	result, err := gen.ExecCommand(gen.GetOpenSSLPath(), password, "rsautl", "-encrypt", "-inkey", encryptCertPath, "-certin")
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	err = gen.RemoveTempFile(encryptCertPath)
	if err != nil {
		return "", fmt.Errorf("failed to remove file - %v", err)
	}

	return gen.EncodeToBase64([]byte(result)), nil
}

// EncryptContract - function to encrypt contract
func EncryptContract(password, section string) (string, error) {
	return EncryptString(password, section)
}

// EncryptString - function to encrypt string
func EncryptString(password, section string) (string, error) {
	err := OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	contractPath, err := gen.CreateTempFile(section)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}

	result, err := gen.ExecCommand(gen.GetOpenSSLPath(), password, "enc", "-aes-256-cbc", "-pbkdf2", "-pass", "stdin", "-in", contractPath)
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	err = gen.RemoveTempFile(contractPath)
	if err != nil {
		return "", fmt.Errorf("failed to remove temp file - %v", err)
	}

	return gen.EncodeToBase64([]byte(result)), nil
}

// EncryptFinalStr - function to get final encrypted section
func EncryptFinalStr(encryptedPassword, encryptedContract string) string {
	return fmt.Sprintf("hyper-protect-basic.%s.%s", encryptedPassword, encryptedContract)
}

// CreateSigningCert - function to generate Signing Certificate
func CreateSigningCert(privateKey, cacert, cakey, csrData, csrPemData string, expiryDays int) (string, error) {
	err := OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	var csr string
	if csrPemData == "" {
		privateKeyPath, err := gen.CreateTempFile(privateKey)
		if err != nil {
			return "", fmt.Errorf("failed to create temp file - %v", err)
		}

		var csrDataMap map[string]interface{}
		err = json.Unmarshal([]byte(csrData), &csrDataMap)
		if err != nil {
			return "", fmt.Errorf("failed to unmarshal JSON - %v", err)
		}

		csrParam := fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%sC/emailAddress=%s", csrDataMap["country"], csrDataMap["state"], csrDataMap["location"], csrDataMap["org"], csrDataMap["unit"], csrDataMap["domain"], csrDataMap["mail"])

		csr, err = gen.ExecCommand(gen.GetOpenSSLPath(), "", "req", "-new", "-key", privateKeyPath, "-subj", csrParam)
		if err != nil {
			return "", fmt.Errorf("failed to execute openssl command - %v", err)
		}

		err = gen.RemoveTempFile(privateKeyPath)
		if err != nil {
			return "", fmt.Errorf("failed to remove temp file - %v", err)
		}

	} else {
		csr = csrPemData
	}

	csrPath, err := gen.CreateTempFile(csr)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}

	caCertPath, err := gen.CreateTempFile(cacert)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}
	caKeyPath, err := gen.CreateTempFile(cakey)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}

	signingCert, err := CreateCert(csrPath, caCertPath, caKeyPath, expiryDays)
	if err != nil {
		return "", fmt.Errorf("failed to create signing certificate - %v", err)
	}

	for _, path := range []string{csrPath, caCertPath, caKeyPath} {
		err := gen.RemoveTempFile(path)
		if err != nil {
			return "", fmt.Errorf("failed to remove temp file - %v", err)
		}
	}

	return gen.EncodeToBase64([]byte(signingCert)), nil
}

// CreateCert - function to create signing certificate
func CreateCert(csrPath, caCertPath, caKeyPath string, expiryDays int) (string, error) {
	signingCert, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "x509", "-req", "-in", csrPath, "-CA", caCertPath, "-CAkey", caKeyPath, "-CAcreateserial", "-days", fmt.Sprintf("%d", expiryDays))
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	return signingCert, nil
}

// SignContract - function to sign encrypted contract
func SignContract(encryptedWorkload, encryptedEnv, privateKey string) (string, error) {
	err := OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	combinedContract := encryptedWorkload + encryptedEnv

	privateKeyPath, err := gen.CreateTempFile(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}

	workloadEnvSignature, err := gen.ExecCommand(gen.GetOpenSSLPath(), combinedContract, "dgst", "-sha256", "-sign", privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	err = gen.RemoveTempFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to remove temp file - %v", err)
	}

	return gen.EncodeToBase64([]byte(workloadEnvSignature)), nil
}

// GenFinalSignedContract - function to generate the final contract
func GenFinalSignedContract(workload, env, workloadEnvSig string) (string, error) {
	contract := map[string]interface{}{
		"workload":             workload,
		"env":                  env,
		"envWorkloadSignature": workloadEnvSig,
	}

	finalContract, err := gen.MapToYaml(contract)
	if err != nil {
		return "", fmt.Errorf("failed to convert MAP to YAML - %v", err)
	}

	return finalContract, nil
}
