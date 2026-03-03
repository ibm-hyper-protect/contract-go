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

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	keylen = 32
)

// OpensslCheck verifies that OpenSSL is installed and accessible.
// It executes the OpenSSL version command to confirm availability.
//
// Returns:
//   - nil if OpenSSL is found and working
//   - Error if OpenSSL is not found or not in PATH
func OpensslCheck() error {
	_, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "version")

	if err != nil {
		return err
	}

	return nil
}

// GeneratePublicKey extracts the public key from an RSA private key.
// It uses OpenSSL to derive the public key in PEM format from the provided private key.
//
// Parameters:
//   - privateKey: RSA private key (PEM format)
//
// Returns:
//   - Public key in PEM format
//   - Error if OpenSSL is not found or key extraction fails
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

// RandomPasswordGenerator generates a cryptographically secure random password.
// It uses OpenSSL to generate 32 bytes of random data for use as an encryption password.
//
// Returns:
//   - Random password string (32 bytes)
//   - Error if OpenSSL is not found or random generation fails
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

// EncryptPassword encrypts a password using RSA encryption with a certificate.
// It uses OpenSSL RSA encryption with the provided certificate and returns the result
// as a Base64-encoded string.
//
// Parameters:
//   - password: Password to encrypt
//   - cert: Encryption certificate (PEM format)
//
// Returns:
//   - Base64-encoded encrypted password
//   - Error if OpenSSL is not found or encryption fails
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

// EncryptContract encrypts a contract section using AES-256-CBC encryption.
// This is a wrapper function that calls EncryptString for contract-specific encryption.
//
// Parameters:
//   - password: Password for AES-256-CBC encryption
//   - section: Contract section to encrypt
//
// Returns:
//   - Base64-encoded encrypted section
//   - Error if encryption fails
func EncryptContract(password, section string) (string, error) {
	return EncryptString(password, section)
}

// EncryptString encrypts any string data using AES-256-CBC with PBKDF2.
// It uses OpenSSL to perform the encryption and returns the result as Base64-encoded data.
//
// Parameters:
//   - password: Password for AES-256-CBC encryption
//   - section: String data to encrypt
//
// Returns:
//   - Base64-encoded encrypted data
//   - Error if OpenSSL is not found or encryption fails
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

// EncryptFinalStr formats the final encrypted section by combining the encrypted password and contract.
// It returns a string in the format "hyper-protect-basic.<password>.<contract>" which is the
// standard format for Hyper Protect encrypted data.
//
// Parameters:
//   - encryptedPassword: Base64-encoded encrypted password
//   - encryptedContract: Base64-encoded encrypted contract data
//
// Returns:
//   - Formatted string in "hyper-protect-basic.<password>.<contract>" format
func EncryptFinalStr(encryptedPassword, encryptedContract string) string {
	return fmt.Sprintf("hyper-protect-basic.%s.%s", encryptedPassword, encryptedContract)
}

// CreateSigningCert generates a signing certificate using a Certificate Authority (CA).
// It can either generate a Certificate Signing Request (CSR) from the provided CSR data and private key,
// or use an existing CSR in PEM format. The certificate is signed by the CA and returned as Base64-encoded data.
//
// Parameters:
//   - privateKey: RSA private key (PEM format) for generating CSR (ignored if csrPemData is provided)
//   - cacert: CA certificate (PEM format) used to sign the certificate
//   - cakey: CA private key (PEM format) used to sign the certificate
//   - csrData: JSON string with CSR fields (country, state, location, org, unit, domain, mail) - ignored if csrPemData is provided
//   - csrPemData: Existing CSR in PEM format (if empty, generates new CSR from csrData and privateKey)
//   - expiryDays: Number of days until certificate expiration
//
// Returns:
//   - Base64-encoded signing certificate
//   - Error if OpenSSL is not found, CSR generation fails, or certificate signing fails
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

// CreateCert creates an X.509 certificate by signing a CSR with a Certificate Authority.
// It uses OpenSSL to generate a certificate from the CSR, signed by the provided CA certificate and key.
//
// Parameters:
//   - csrPath: File path to the Certificate Signing Request (PEM format)
//   - caCertPath: File path to the CA certificate (PEM format)
//   - caKeyPath: File path to the CA private key (PEM format)
//   - expiryDays: Number of days until certificate expiration
//
// Returns:
//   - Signed certificate in PEM format
//   - Error if OpenSSL execution fails or certificate generation fails
func CreateCert(csrPath, caCertPath, caKeyPath string, expiryDays int) (string, error) {
	signingCert, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "x509", "-req", "-in", csrPath, "-CA", caCertPath, "-CAkey", caKeyPath, "-CAcreateserial", "-days", fmt.Sprintf("%d", expiryDays))
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	return signingCert, nil
}

// SignContract creates a digital signature for an encrypted contract using an RSA private key.
// It combines the encrypted workload and environment sections, then generates a SHA-256 signature
// using the private key. The signature is returned as Base64-encoded data.
//
// Parameters:
//   - encryptedWorkload: Encrypted workload section of the contract
//   - encryptedEnv: Encrypted environment section of the contract
//   - privateKey: RSA private key (PEM format) used to sign the contract
//
// Returns:
//   - Base64-encoded SHA-256 signature of the combined contract sections
//   - Error if OpenSSL is not found or signing fails
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

// GenFinalSignedContract assembles the final signed contract in YAML format.
// It combines the encrypted workload, environment, and signature into a structured contract
// that can be deployed to Hyper Protect services.
//
// Parameters:
//   - workload: Encrypted workload section (Base64-encoded)
//   - env: Encrypted environment section (Base64-encoded)
//   - workloadEnvSignature: Base64-encoded signature of the workload and environment
//   - attestationPublicKey: plain text or Base64-encoded attestation public key
//
// Returns:
//   - Final contract in YAML format with workload, env, envWorkloadSignature and attestationPublicKey (optional) fields
//   - Error if YAML conversion fails
func GenFinalSignedContract(workload, env, workloadEnvSignature, attestationPublicKey string) (string, error) {
	contract := map[string]interface{}{
		"workload":             workload,
		"env":                  env,
		"envWorkloadSignature": workloadEnvSignature,
	}

	if attestationPublicKey != "" {
		contract["attestationPublicKey"] = attestationPublicKey
	}

	finalContract, err := gen.MapToYaml(contract)
	if err != nil {
		return "", fmt.Errorf("failed to convert MAP to YAML - %v", err)
	}

	return finalContract, nil
}

// ExtractPublicKeyFromCert extracts the public key from an X.509 certificate.
// It uses OpenSSL to extract the RSA public key in PEM format from the provided certificate.
//
// Parameters:
//   - cert: X.509 certificate in PEM format
//
// Returns:
//   - Public key in PEM format
//   - Error if OpenSSL is not found or key extraction fails
func ExtractPublicKeyFromCert(cert string) (string, error) {
	err := OpensslCheck()
	if err != nil {
		return "", fmt.Errorf("openssl not found - %v", err)
	}

	certPath, err := gen.CreateTempFile(cert)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}

	publicKey, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "x509", "-in", certPath, "-pubkey", "-noout")
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}

	err = gen.RemoveTempFile(certPath)
	if err != nil {
		return "", fmt.Errorf("failed to remove temp file - %v", err)
	}

	return publicKey, nil
}

// VerifySignature verifies a digital signature against data using a public key.
// It uses OpenSSL to verify the SHA-256 signature with the provided public key.
//
// Parameters:
//   - data: Original data that was signed
//   - signature: Binary signature data to verify
//   - publicKey: RSA public key in PEM format
//
// Returns:
//   - nil if signature verification succeeds
//   - Error if OpenSSL is not found or verification fails
func VerifySignature(data string, signature []byte, publicKey string) error {
	err := OpensslCheck()
	if err != nil {
		return fmt.Errorf("openssl not found - %v", err)
	}

	dataPath, err := gen.CreateTempFile(data)
	if err != nil {
		return fmt.Errorf("failed to create temp file for data - %v", err)
	}

	signaturePath, err := gen.CreateTempFile(string(signature))
	if err != nil {
		return fmt.Errorf("failed to create temp file for signature - %v", err)
	}

	publicKeyPath, err := gen.CreateTempFile(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create temp file for public key - %v", err)
	}

	_, err = gen.ExecCommand(gen.GetOpenSSLPath(), "", "dgst", "-sha256", "-verify", publicKeyPath, "-signature", signaturePath, dataPath)
	if err != nil {
		return err
	}

	for _, path := range []string{dataPath, signaturePath, publicKeyPath} {
		err := gen.RemoveTempFile(path)
		if err != nil {
			return fmt.Errorf("failed to remove temp file - %v", err)
		}
	}

	return nil
}
