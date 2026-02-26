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

package contract

import (
	"bytes"
	"fmt"
	"text/template"

	"gopkg.in/yaml.v3"

	dec "github.com/ibm-hyper-protect/contract-go/v2/common/decrypt"
	enc "github.com/ibm-hyper-protect/contract-go/v2/common/encrypt"
	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	emptyParameterErrStatement = "required parameter is empty"
)

// HPCC initdata.toml file template.
const tomlTemplate = `
algorithm = "sha384"
version = "0.1.0"

[data]
"contract.yaml" = '''{{ . }}'''
`

// HpcrText generates Base64-encoded representation of plain text with integrity checksums.
// It encodes the provided text and returns both the encoded data and SHA256 checksums
// for verification purposes.
//
// Parameters:
//   - plainText: Text data to encode
//
// Returns:
//   - Base64-encoded text
//   - SHA256 hash of the original text
//   - SHA256 hash of the Base64-encoded data
//   - Error if plainText is empty
func HpcrText(plainText string) (string, string, string, error) {
	if gen.CheckIfEmpty(plainText) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	hpcrTextStr := gen.EncodeToBase64([]byte(plainText))

	return hpcrTextStr, gen.GenerateSha256(plainText), gen.GenerateSha256(hpcrTextStr), nil
}

// HpcrJson generates Base64-encoded representation of JSON data with integrity checksums.
// It validates the JSON format, encodes it, and returns the encoded data along with
// SHA256 checksums for verification.
//
// Parameters:
//   - plainJson: Valid JSON string to encode
//
// Returns:
//   - Base64-encoded JSON
//   - SHA256 hash of the original JSON
//   - SHA256 hash of the Base64-encoded data
//   - Error if JSON is invalid
func HpcrJson(plainJson string) (string, string, string, error) {
	if !gen.IsJSON(plainJson) {
		return "", "", "", fmt.Errorf("not a JSON data")
	}

	hpcrJsonStr := gen.EncodeToBase64([]byte(plainJson))

	return hpcrJsonStr, gen.GenerateSha256(plainJson), gen.GenerateSha256(hpcrJsonStr), nil
}

// HpcrTextEncrypted encrypts plain text using the Hyper Protect encryption format.
// It generates a random password, encrypts the text, and returns the encrypted data
// in the format "hyper-protect-basic.<password>.<data>" along with checksums.
//
// Parameters:
//   - plainText: Text to encrypt
//   - hyperProtectOs: Target platform - "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (defaults to "hpvs" if empty)
//   - encryptionCertificate: PEM certificate for encryption (uses embedded default if empty)
//
// Returns:
//   - Encrypted data in format "hyper-protect-basic.<password>.<data>"
//   - SHA256 hash of the original text
//   - SHA256 hash of the encrypted output
//   - Error if encryption fails
func HpcrTextEncrypted(plainText, hyperProtectOs, encryptionCertificate string) (string, string, string, error) {
	if gen.CheckIfEmpty(plainText) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	hpcrTextEncryptedStr, err := encrypter(plainText, hyperProtectOs, encryptionCertificate)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate encrypted string - %v", err)
	}

	return hpcrTextEncryptedStr, gen.GenerateSha256(plainText), gen.GenerateSha256(hpcrTextEncryptedStr), nil
}

// HpcrTextDecrypted decrypts hyper protect encrypted data
// It decrypts the text encrypted in format hyper-protect-basic
//
// Parameters:
//   - encryptedText: Encrypted text
//   - privateKey: Private key to decrypt the text
//
// Returns:
//   - Decrypted text
//   - SHA256 hash of the encrypted text
//   - SHA256 hash of the decrypted output
//   - Error if decryption fails
func HpcrTextDecrypted(encryptedText, privateKey string) (string, string, string, error) {
	if gen.CheckIfEmpty(encryptedText, privateKey) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	decryptedText, err := dec.DecryptText(encryptedText, privateKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to decrypt text - %v", err)
	}

	return decryptedText, gen.GenerateSha256(encryptedText), gen.GenerateSha256(decryptedText), nil
}

// HpcrJsonEncrypted encrypts JSON data using the Hyper Protect encryption format.
// It validates the JSON, generates a random password, encrypts the data, and returns
// the encrypted output in the Hyper Protect format along with checksums.
//
// Parameters:
//   - plainJson: Valid JSON string to encrypt
//   - hyperProtectOs: Target platform - "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (defaults to "hpvs" if empty)
//   - encryptionCertificate: PEM certificate for encryption (uses embedded default if empty)
//
// Returns:
//   - Encrypted JSON in format "hyper-protect-basic.<password>.<data>"
//   - SHA256 hash of the original JSON
//   - SHA256 hash of the encrypted output
//   - Error if JSON is invalid or encryption fails
func HpcrJsonEncrypted(plainJson, hyperProtectOs, encryptionCertificate string) (string, string, string, error) {
	if !gen.IsJSON(plainJson) {
		return "", "", "", fmt.Errorf("contract is not a JSON data")
	}

	hpcrJsonEncrypted, err := encrypter(plainJson, hyperProtectOs, encryptionCertificate)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate encrypted JSON - %v", err)
	}

	return hpcrJsonEncrypted, gen.GenerateSha256(plainJson), gen.GenerateSha256(hpcrJsonEncrypted), nil
}

// HpcrTgz creates a Base64-encoded TGZ archive from a directory containing docker-compose.yaml or pods.yaml.
// It reads all files in the specified folder, creates a tar.gz archive, encodes it to Base64,
// and returns the encoded archive along with checksums.
//
// Parameters:
//   - folderPath: Path to folder containing docker-compose.yaml or pods.yaml files
//
// Returns:
//   - Base64-encoded tar.gz archive
//   - SHA256 hash of the folder path
//   - SHA256 hash of the Base64-encoded TGZ
//   - Error if folder doesn't exist or archive creation fails
func HpcrTgz(folderPath string) (string, string, string, error) {
	if gen.CheckIfEmpty(folderPath) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	if !gen.CheckFileFolderExists(folderPath) {
		return "", "", "", fmt.Errorf("folder doesn't exists - %s", folderPath)
	}

	filesFoldersList, err := gen.ListFoldersAndFiles(folderPath)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get files and folder under path - %v", err)
	}

	tgzBase64, err := gen.GenerateTgzBase64(filesFoldersList)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get base64 tgz - %v", err)
	}

	return tgzBase64, gen.GenerateSha256(folderPath), gen.GenerateSha256(tgzBase64), nil
}

// HpcrTgzEncrypted creates an encrypted Base64 TGZ archive from a directory.
// It first creates a Base64-encoded tar.gz archive from the folder, then encrypts it
// using the Hyper Protect encryption format.
//
// Parameters:
//   - folderPath: Path to folder containing docker-compose.yaml or pods.yaml files
//   - hyperProtectOs: Target platform - "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (defaults to "hpvs" if empty)
//   - encryptionCertificate: PEM certificate for encryption (uses embedded default if empty)
//
// Returns:
//   - Encrypted TGZ in format "hyper-protect-basic.<password>.<data>"
//   - SHA256 hash of the folder path
//   - SHA256 hash of the encrypted output
//   - Error if folder is invalid or encryption fails
func HpcrTgzEncrypted(folderPath, hyperProtectOs, encryptionCertificate string) (string, string, string, error) {
	if gen.CheckIfEmpty(folderPath) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	tgzBase64, _, _, err := HpcrTgz(folderPath)
	if err != nil {
		return "", "", "", err
	}

	hpcrTgzEncryptedStr, err := encrypter(tgzBase64, hyperProtectOs, encryptionCertificate)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate encrypted tgz - %v", err)
	}

	return hpcrTgzEncryptedStr, gen.GenerateSha256(folderPath), gen.GenerateSha256(hpcrTgzEncryptedStr), nil
}

// HpcrVerifyContract validates a contract against the JSON schema for the specified Hyper Protect platform.
// It checks the contract structure, required fields, data types, and platform-specific requirements
// to ensure the contract is valid before encryption and deployment.
//
// Parameters:
//   - contract: YAML contract string to validate
//   - version: Platform identifier - "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (defaults to "hpvs" if empty)
//
// Returns:
//   - nil if contract is valid
//   - Error if validation fails with details about what's wrong
func HpcrVerifyContract(contract, version string) error {
	return gen.VerifyContractWithSchema(contract, version)
}

// HpcrContractSignedEncrypted generates a signed and encrypted contract ready for deployment to Hyper Protect services.
// It validates the contract schema, generates a public key from the private key, encrypts the workload
// and environment sections, injects the signing key, and signs the encrypted sections with the private key.
//
// Parameters:
//   - contract: YAML contract string with env and workload sections
//   - hyperProtectOs: Target platform - "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (defaults to "hpvs" if empty)
//   - encryptionCertificate: PEM certificate for encryption (uses embedded default if empty)
//   - privateKey: RSA private key (PEM format) for signing the contract
//
// Returns:
//   - Signed and encrypted contract YAML with workload, env, and envWorkloadSignature
//   - SHA256 hash of the original contract
//   - SHA256 hash of the final signed contract
//   - Error if validation, encryption, or signing fails
func HpcrContractSignedEncrypted(contract, hyperProtectOs, encryptionCertificate, privateKey string) (string, string, string, error) {
	err := HpcrVerifyContract(contract, hyperProtectOs)
	if err != nil {
		return "", "", "", fmt.Errorf("schema verification failed - %v", err)
	}

	if gen.CheckIfEmpty(contract, privateKey) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	encryptCertificate, err := gen.FetchEncryptionCertificate(hyperProtectOs, encryptionCertificate)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to fetch encryption certificate - %v", err)
	}

	_, err = gen.CheckEncryptionCertValidityForContractEncryption(encryptCertificate)
	if err != nil {
		return "", "", "", fmt.Errorf("Failed to encrypt contract - %v", err)
	}

	publicKey, err := enc.GeneratePublicKey(privateKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate public key - %v", err)
	}

	signedEncryptContract, err := encryptWrapper(contract, hyperProtectOs, encryptCertificate, privateKey, publicKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to sign and encrypt contract - %v", err)
	}

	return signedEncryptContract, gen.GenerateSha256(contract), gen.GenerateSha256(signedEncryptContract), nil
}

// HpcrContractSignedEncryptedContractExpiry generates a signed and encrypted contract with time-based expiration.
// It creates a signing certificate with expiration using a Certificate Authority, then signs and encrypts
// the contract. This is used for production deployments requiring time-limited contracts.
//
// Parameters:
//   - contract: YAML contract string with env and workload sections
//   - hyperProtectOs: Target platform - "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (defaults to "hpvs" if empty)
//   - encryptionCertificate: PEM certificate for encryption (uses embedded default if empty)
//   - privateKey: RSA private key (PEM format) for signing the contract
//   - cacert: CA certificate (PEM format) for creating the signing certificate
//   - caKey: CA private key (PEM format) for signing the certificate
//   - csrDataStr: CSR parameters as JSON string (use if not providing csrPemData)
//   - csrPemData: CSR in PEM format (use if not providing csrDataStr)
//   - expiryDays: Number of days until the contract expires
//
// Note: Either csrDataStr OR csrPemData must be provided, but not both.
//
// Returns:
//   - Signed and encrypted contract YAML with time-limited signature
//   - SHA256 hash of the original contract
//   - SHA256 hash of the final signed contract
//   - Error if validation, CSR generation, or signing fails
func HpcrContractSignedEncryptedContractExpiry(contract, hyperProtectOs, encryptionCertificate, privateKey, cacert, caKey, csrDataStr, csrPemData string, expiryDays int) (string, string, string, error) {
	err := HpcrVerifyContract(contract, hyperProtectOs)
	if err != nil {
		return "", "", "", fmt.Errorf("schema verification failed - %v", err)
	}

	if gen.CheckIfEmpty(contract, privateKey, cacert, caKey) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	if csrPemData == "" && csrDataStr == "" || len(csrPemData) > 0 && len(csrDataStr) > 0 {
		return "", "", "", fmt.Errorf("the CSR parameters and CSR PEM file are parsed together or both are nil")
	}

	signingCert, err := enc.CreateSigningCert(privateKey, cacert, caKey, csrDataStr, csrPemData, expiryDays)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate signing certificate - %v", err)
	}

	finalContract, err := encryptWrapper(contract, hyperProtectOs, encryptionCertificate, privateKey, signingCert)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate signed and encrypted contract - %v", err)
	}

	return finalContract, gen.GenerateSha256(contract), gen.GenerateSha256(finalContract), nil
}

// HpccInitdata generates a gzipped and encoded initdata string.
// It creates the initdata.toml based on tomltemplate and gzip the initdata.toml content to compress data.
// It encode the compressed content in base64.
//
// Parameters:
// - contract: Encrypted and singed contract string with env, workload section
//
// Returns:
//   - Gzipped & Encoded initdata string
//   - SHA256 hash of the original contract
//   - SHA256 hash of the gzipped and encoded initdata string
//   - Error if validation, gzip or encoding fails
func HpccInitdata(contract string) (string, string, string, error) {

	var buf bytes.Buffer

	if gen.CheckIfEmpty(contract) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	tmpl, err := template.New("toml").Parse(tomlTemplate)
	if err != nil {
		return "", "", "", fmt.Errorf("failed while parsing the template toml %v", err)
	}

	err = tmpl.Execute(&buf, contract)
	if err != nil {
		return "", "", "", fmt.Errorf("failed while creating initdata.toml %v", err)
	}
	inidataString := buf.String()

	compressedBytes, err := gen.GzipInitData(inidataString)
	if err != nil {
		return "", "", "", fmt.Errorf("failed while gzipping initdata %v", err)
	}

	encodedString := gen.EncodeToBase64(compressedBytes)
	return encodedString, gen.GenerateSha256(contract), gen.GenerateSha256(encodedString), nil
}

// encryptWrapper is a helper function that signs and encrypts a contract.
// It handles both regular signing and signing with contract expiry by accepting a publicKey
// parameter that can be either a regular public key or a time-limited signing certificate.
// The function encrypts the workload and env sections separately, injects the signing key,
// and creates a signature over the encrypted sections.
//
// Parameters:
//   - contract: YAML contract string with env and workload sections
//   - hyperProtectOs: Target platform - "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (default: hpvs)
//   - encryptionCertificate: PEM certificate for encryption (optional)
//   - privateKey: RSA private key (PEM format) for signing
//   - publicKey: Public key or signing certificate (PEM format)
//
// Returns:
//   - Final contract YAML with encrypted workload, env, and envWorkloadSignature
//   - Error if encryption or signing fails
func encryptWrapper(contract, hyperProtectOs, encryptionCertificate, privateKey, publicKey string) (string, error) {
	if gen.CheckIfEmpty(contract, privateKey, publicKey) {
		return "", fmt.Errorf(emptyParameterErrStatement)
	}

	var contractMap map[string]interface{}

	encryptCertificate, err := gen.FetchEncryptionCertificate(hyperProtectOs, encryptionCertificate)
	if err != nil {
		return "", fmt.Errorf("failed to fetch encryption certificate - %v", err)
	}

	err = yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal YAML - %v", err)
	}

	encryptedWorkload, err := encrypter(contractMap["workload"].(string), hyperProtectOs, encryptCertificate)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt workload - %v", err)
	}

	updatedEnv, err := gen.KeyValueInjector(contractMap["env"].(string), "signingKey", gen.EncodeToBase64([]byte(publicKey)))
	if err != nil {
		return "", fmt.Errorf("failed to inject signingKey to env - %v", err)
	}

	encryptedEnv, err := encrypter(updatedEnv, hyperProtectOs, encryptCertificate)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt env - %v", err)
	}

	workloadEnvSignature, err := enc.SignContract(encryptedWorkload, encryptedEnv, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign contract - %v", err)
	}

	attestationPublicKey, _ := contractMap["attestationPublicKey"].(string)
	var encryptedAttestationPublicKey string
	if attestationPublicKey != "" {
		encryptedAttestationPublicKey, err = encrypter(attestationPublicKey, hyperProtectOs, encryptCertificate)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt attestationPublicKey - %v", err)
		}
	}

	finalContract, err := enc.GenFinalSignedContract(encryptedWorkload, encryptedEnv, workloadEnvSignature, encryptedAttestationPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate final contract - %v", err)
	}

	return finalContract, nil
}

// encrypter is a helper function that encrypts any string data using the Hyper Protect encryption format.
// It generates a random password, encrypts it with the encryption certificate, encrypts the data
// with the password, and returns the result in the format "hyper-protect-basic.<password>.<data>".
// This function is used internally by all encryption functions (HpcrTextEncrypted, HpcrJsonEncrypted, etc.).
//
// Parameters:
//   - stringText: String data to encrypt (text, JSON, or Base64-encoded TGZ)
//   - hyperProtectOs: Target platform - "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (default: hpvs)
//   - encryptionCertificate: PEM certificate for encryption (optional)
//
// Returns:
//   - Encrypted string in format "hyper-protect-basic.<password>.<data>"
//   - Error if encryption fails or certificate is invalid
func encrypter(stringText, hyperProtectOs, encryptionCertificate string) (string, error) {
	if gen.CheckIfEmpty(stringText) {
		return "", fmt.Errorf(emptyParameterErrStatement)
	}

	encCert, err := gen.FetchEncryptionCertificate(hyperProtectOs, encryptionCertificate)
	if err != nil {
		return "", fmt.Errorf("failed to fetch encryption certificate - %v", err)
	}

	password, err := enc.RandomPasswordGenerator()
	if err != nil {
		return "", fmt.Errorf("failed to generate random password - %v", err)
	}

	encodedEncryptedPassword, err := enc.EncryptPassword(password, encCert)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt password - %v", err)
	}

	encryptedString, err := enc.EncryptString(password, stringText)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key - %v", err)
	}

	return enc.EncryptFinalStr(encodedEncryptedPassword, encryptedString), nil
}
