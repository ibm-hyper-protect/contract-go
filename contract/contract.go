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

// HpcrText encodes plain text to Base64 with integrity checksums.
//
// Use this function when you need to Base64-encode text content (such as certificates, keys, etc.) for inclusion in an IBM Confidential Computing
// contract. The returned SHA256 checksums allow you to verify data integrity at each stage.
//
// Parameters:
//   - plainText: Text data to encode (must not be empty)
//
// Returns:
//   - Base64-encoded text
//   - SHA256 hash of the original plain text (input checksum)
//   - SHA256 hash of the Base64-encoded output (output checksum)
//   - Error if plainText is empty
func HpcrText(plainText string) (string, string, string, error) {
	if gen.CheckIfEmpty(plainText) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	hpcrTextStr := gen.EncodeToBase64([]byte(plainText))

	return hpcrTextStr, gen.GenerateSha256(plainText), gen.GenerateSha256(hpcrTextStr), nil
}

// HpcrJson encodes JSON data to Base64 with integrity checksums.
//
// Use this function when you need to Base64-encode valid JSON content for inclusion in an
// IBM Confidential Computing contract. The JSON is validated before encoding. The returned
// SHA256 checksums allow you to verify data integrity at each stage.
//
// Parameters:
//   - plainJson: Valid JSON string to encode (validated before encoding)
//
// Returns:
//   - Base64-encoded JSON
//   - SHA256 hash of the original JSON (input checksum)
//   - SHA256 hash of the Base64-encoded output (output checksum)
//   - Error if the input is not valid JSON
func HpcrJson(plainJson string) (string, string, string, error) {
	if !gen.IsJSON(plainJson) {
		return "", "", "", fmt.Errorf("not a JSON data")
	}

	hpcrJsonStr := gen.EncodeToBase64([]byte(plainJson))

	return hpcrJsonStr, gen.GenerateSha256(plainJson), gen.GenerateSha256(hpcrJsonStr), nil
}

// HpcrTextEncrypted encrypts plain text using the IBM Confidential Computing encryption format.
//
// Use this function to encrypt individual contract sections (workload or env) before assembling
// the final contract YAML. The output follows the format "hyper-protect-basic.<encrypted-password>.<encrypted-data>",
// where the password is RSA-encrypted with the IBM encryption certificate and the data is
// AES-256-CBC encrypted with the password.
//
// Parameters:
//   - plainText: Text to encrypt (must not be empty)
//   - hyperProtectOs: Target platform identifier — "hpvs" (IBM Confidential Computing Container Runtime),
//     "hpcr-rhvs" (for Red Hat Virtualization Solutions), or "hpcc-peerpod" (for Red Hat OpenShift).
//     Defaults to "hpvs" if empty.
//   - encryptionCertificate: PEM-formatted IBM encryption certificate. If empty, the library
//     uses the embedded default certificate for the specified platform.
//
// Returns:
//   - Encrypted data in format "hyper-protect-basic.<encrypted-password>.<encrypted-data>"
//   - SHA256 hash of the original text (input checksum)
//   - SHA256 hash of the encrypted output (output checksum)
//   - Error if encryption fails or certificate is invalid
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

// HpcrTextDecrypted decrypts data encrypted with the IBM Confidential Computing encryption format.
//
// Use this function to decrypt text that was encrypted using [HpcrTextEncrypted] or the equivalent
// openssl-based encryption process documented in the IBM Confidential Computing documentation.
// The input must be in the format "hyper-protect-basic.<encrypted-password>.<encrypted-data>".
//
// Parameters:
//   - encryptedText: Encrypted text in format "hyper-protect-basic.<encrypted-password>.<encrypted-data>"
//   - privateKey: RSA private key (PEM format) corresponding to the encryption certificate used during encryption
//   - password: Optional password to unlock the encrypted private key (empty string "" for unencrypted keys)
//
// Returns:
//   - Decrypted plain text
//   - SHA256 hash of the encrypted input (input checksum)
//   - SHA256 hash of the decrypted output (output checksum)
//   - Error if decryption fails or parameters are missing
func HpcrTextDecrypted(encryptedText, privateKey, password string) (string, string, string, error) {
	if gen.CheckIfEmpty(encryptedText, privateKey) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	decryptedText, err := dec.DecryptText(encryptedText, privateKey, password)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to decrypt text - %v", err)
	}

	return decryptedText, gen.GenerateSha256(encryptedText), gen.GenerateSha256(decryptedText), nil
}

// HpcrJsonEncrypted encrypts JSON data using the IBM Confidential Computing encryption format.
//
// Use this function to encrypt JSON-formatted contract sections. The JSON is validated before
// encryption. The output follows the format "hyper-protect-basic.<encrypted-password>.<encrypted-data>".
//
// Parameters:
//   - plainJson: Valid JSON string to encrypt
//   - hyperProtectOs: Target platform identifier — "hpvs" (IBM Confidential Computing Container Runtime),
//     "hpcr-rhvs" (for Red Hat Virtualization Solutions), or "hpcc-peerpod" (for Red Hat OpenShift).
//     Defaults to "hpvs" if empty.
//   - encryptionCertificate: PEM-formatted IBM encryption certificate. If empty, the library
//     uses the embedded default certificate for the specified platform.
//
// Returns:
//   - Encrypted JSON in format "hyper-protect-basic.<encrypted-password>.<encrypted-data>"
//   - SHA256 hash of the original JSON (input checksum)
//   - SHA256 hash of the encrypted output (output checksum)
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

// HpcrTgz creates a Base64-encoded TGZ archive from a directory.
//
// Use this function to prepare the compose archive for the workload section of a contract.
// The folder should contain your docker-compose.yaml (for single-container deployments)
// or pod descriptor YAML files (for multi-container deployments). The resulting Base64-encoded
// TGZ is used as the value for the compose->archive or play->archive field in the contract.
//
// Parameters:
//   - folderPath: Absolute path to folder containing docker-compose.yaml, pods.yaml, or pod descriptor files
//
// Returns:
//   - Base64-encoded tar.gz archive (ready for use in compose->archive)
//   - SHA256 hash of the folder path (input checksum)
//   - SHA256 hash of the Base64-encoded TGZ (output checksum)
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

// HpcrTgzEncrypted creates an encrypted TGZ archive from a directory.
//
// Use this function to prepare and encrypt the compose archive for the workload section
// of a contract in a single step. This combines [HpcrTgz] and [HpcrTextEncrypted] — it first
// archives the folder contents into a Base64-encoded TGZ, then encrypts it using the IBM
// Confidential Computing encryption format.
//
// Parameters:
//   - folderPath: Absolute path to folder containing docker-compose.yaml, pods.yaml, or pod descriptor files
//   - hyperProtectOs: Target platform identifier — "hpvs", "hpcr-rhvs", or "hpcc-peerpod".
//     Defaults to "hpvs" if empty.
//   - encryptionCertificate: PEM-formatted IBM encryption certificate. If empty, the library
//     uses the embedded default certificate for the specified platform.
//
// Returns:
//   - Encrypted TGZ in format "hyper-protect-basic.<encrypted-password>.<encrypted-data>"
//   - SHA256 hash of the folder path (input checksum)
//   - SHA256 hash of the encrypted output (output checksum)
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

// HpcrVerifyContract validates a contract YAML against the platform-specific JSON schema.
//
// Use this function to validate your contract before signing and encrypting it. It checks
// the contract structure, required fields, data types, and platform-specific requirements
// to catch errors early, before deployment. It is recommended to call this function before
// [HpcrContractSignedEncrypted] or [HpcrContractSignedEncryptedContractExpiry].
//
// Parameters:
//   - contract: YAML contract string to validate (must contain workload and env sections)
//   - version: Platform identifier — "hpvs" (IBM Confidential Computing Container Runtime),
//     "hpcr-rhvs" (for Red Hat Virtualization Solutions), or "hpcc-peerpod" (for Red Hat OpenShift).
//     Defaults to "hpvs" if empty.
//
// Returns:
//   - nil if the contract is valid
//   - Error with details about validation failures
func HpcrVerifyContract(contract, version string) error {
	return gen.VerifyContractWithSchema(contract, version)
}

// HpcrContractSignedEncrypted generates a production-ready signed and encrypted contract.
//
// This is the primary function for creating deployment-ready contracts for IBM Confidential Computing.
// It performs the complete contract preparation workflow:
//  1. Validates the contract against the platform-specific schema
//  2. Fetches the encryption certificate (from the embedded default or a user-provided certificate)
//  3. Generates a public key from the provided private key
//  4. Encrypts the workload and env sections separately
//  5. Injects the signing key into the env section
//  6. Signs the encrypted sections and sets the envWorkloadSignature
//
// The output contract is ready to be passed as user-data when creating a virtual server instance.
//
// Parameters:
//   - contract: YAML contract string with workload and env sections (and optionally attestationPublicKey)
//   - hyperProtectOs: Target platform identifier — "hpvs" (IBM Confidential Computing Container Runtime),
//     "hpcr-rhvs" (for Red Hat Virtualization Solutions), or "hpcc-peerpod" (for Red Hat OpenShift).
//     Defaults to "hpvs" if empty.
//   - encryptionCertificate: PEM-formatted IBM encryption certificate. If empty, the library
//     uses the embedded default certificate for the specified platform.
//   - privateKey: RSA private key (PEM format) for signing the contract.
//     Generate with: openssl genrsa -out private.pem 4096
//   - password: Optional password to unlock the encrypted private key (empty string "" for unencrypted keys)
//
// Returns:
//   - Signed and encrypted contract YAML containing workload, env, and envWorkloadSignature sections
//   - SHA256 hash of the original contract (input checksum)
//   - SHA256 hash of the final signed contract (output checksum)
//   - Error if validation, encryption, or signing fails
func HpcrContractSignedEncrypted(contract, hyperProtectOs, encryptionCertificate, privateKey, password string) (string, string, string, error) {
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

	publicKey, err := enc.GeneratePublicKey(privateKey, password)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate public key - %v", err)
	}

	signedEncryptContract, err := encryptWrapper(contract, hyperProtectOs, encryptCertificate, privateKey, password, publicKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to sign and encrypt contract - %v", err)
	}

	return signedEncryptContract, gen.GenerateSha256(contract), gen.GenerateSha256(signedEncryptContract), nil
}

// HpcrContractSignedEncryptedContractExpiry generates a signed and encrypted contract with time-based expiration.
//
// Use this function for production deployments that require time-limited contracts. When a contract
// has an expiry, an IBM Confidential Computing instance will refuse to boot if the contract's signing
// certificate has expired. This provides an additional security layer by ensuring contracts cannot be
// reused beyond their intended validity period.
//
// The function creates a signing certificate with an expiration date using a Certificate Authority (CA),
// then signs and encrypts the contract. You must provide either CSR parameters as JSON (csrDataStr)
// or a pre-generated CSR in PEM format (csrPemData), but not both.
//
// Parameters:
//   - contract: YAML contract string with workload and env sections
//   - hyperProtectOs: Target platform identifier — "hpvs", "hpcr-rhvs", or "hpcc-peerpod".
//     Defaults to "hpvs" if empty.
//   - encryptionCertificate: PEM-formatted IBM encryption certificate. If empty, the library
//     uses the embedded default certificate.
//   - privateKey: RSA private key (PEM format) for signing the contract
//   - password: Optional password to unlock the encrypted private key (empty string "" for unencrypted keys)
//   - cacert: CA certificate (PEM format) used to issue the time-limited signing certificate
//   - caKey: CA private key (PEM format) used to sign the time-limited certificate
//   - csrDataStr: Certificate Signing Request parameters as JSON string.
//     Provide this OR csrPemData, not both.
//   - csrPemData: Pre-generated Certificate Signing Request in PEM format.
//     Provide this OR csrDataStr, not both.
//   - expiryDays: Number of days until the contract expires (must be > 0)
//
// Returns:
//   - Signed and encrypted contract YAML with a time-limited signature
//   - SHA256 hash of the original contract (input checksum)
//   - SHA256 hash of the final signed contract (output checksum)
//   - Error if validation, CSR generation, certificate creation, or signing fails
func HpcrContractSignedEncryptedContractExpiry(contract, hyperProtectOs, encryptionCertificate, privateKey, password, cacert, caKey, csrDataStr, csrPemData string, expiryDays int) (string, string, string, error) {
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

	finalContract, err := encryptWrapper(contract, hyperProtectOs, encryptionCertificate, privateKey, password, signingCert)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate signed and encrypted contract - %v", err)
	}

	return finalContract, gen.GenerateSha256(contract), gen.GenerateSha256(finalContract), nil
}

// HpcrContractSign signs an already-encrypted contract without performing encryption.
//
// Use this function when you have already encrypted the workload and env sections of a contract
// yourself (e.g., using openssl commands or [HpcrTextEncrypted]) and only need to add the
// envWorkloadSignature. The contract must be a valid YAML with encrypted workload and env values.
//
// For most use cases, prefer [HpcrContractSignedEncrypted] which handles both encryption and signing.
//
// Parameters:
//   - contract: YAML contract string with pre-encrypted workload and env sections
//   - privateKey: RSA private key (PEM format) used to generate the signature
//   - password: Optional password to unlock the encrypted private key (empty string "" for unencrypted keys)
//
// Returns:
//   - Signed contract YAML with workload, env, and envWorkloadSignature sections
//   - SHA256 hash of the original contract (input checksum)
//   - SHA256 hash of the final signed contract (output checksum)
//   - Error if YAML parsing or signing fails
func HpcrContractSign(contract, privateKey, password string) (string, string, string, error) {
	var contractMap map[string]interface{}

	err := yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to unmarshal YAML - %v", err)
	}

	workload := contractMap["workload"].(string)
	env := contractMap["env"].(string)

	workloadEnvSignature, err := enc.SignContract(workload, env, privateKey, password)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to sign contract - %v", err)
	}

	attestationPublicKey, _ := contractMap["attestationPublicKey"].(string)

	finalContract, err := enc.GenFinalSignedContract(workload, env, workloadEnvSignature, attestationPublicKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate final contract - %v", err)
	}

	return finalContract, gen.GenerateSha256(contract), gen.GenerateSha256(finalContract), nil
}

// HpccInitdata generates gzipped and Base64-encoded initdata for IBM Confidential Computing
// Containers for Red Hat OpenShift Container Platform (HPCC) peer pod deployments.
//
// Use this function to prepare initdata for Kata Containers peer pod VMs on OpenShift.
// The initdata is a TOML file containing the contract, which is gzipped and Base64-encoded
// for efficient transmission. The output is passed as the initdata parameter when creating
// a peer pod VM.
//
// Parameters:
//   - contract: Signed and encrypted contract string (output from [HpcrContractSignedEncrypted]
//     or [HpcrContractSignedEncryptedContractExpiry]). Must contain workload and env sections.
//
// Returns:
//   - Gzipped and Base64-encoded initdata string (ready for peer pod VM creation)
//   - SHA256 hash of the original contract (input checksum)
//   - SHA256 hash of the encoded initdata string (output checksum)
//   - Error if the contract is empty, template parsing fails, or gzip/encoding fails
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

// encryptWrapper is an internal helper that signs and encrypts a contract.
// It handles both regular signing and signing with contract expiry by accepting a publicKey
// parameter that can be either a regular public key or a time-limited signing certificate.
// The function encrypts the workload and env sections separately, injects the signing key
// into the env section, and creates a signature over the encrypted sections.
//
// Parameters:
//   - contract: YAML contract string with workload and env sections
//   - hyperProtectOs: Target platform — "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (default: hpvs)
//   - encryptionCertificate: PEM-formatted encryption certificate (optional, uses default if empty)
//   - privateKey: RSA private key (PEM format) for signing
//   - password: Optional password to unlock the encrypted private key (empty string "" for unencrypted keys)
//   - publicKey: Public key or signing certificate (PEM format) to inject into the env section
//
// Returns:
//   - Final contract YAML with encrypted workload, env, and envWorkloadSignature
//   - Error if encryption or signing fails
func encryptWrapper(contract, hyperProtectOs, encryptionCertificate, privateKey, password, publicKey string) (string, error) {
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

	workloadEnvSignature, err := enc.SignContract(encryptedWorkload, encryptedEnv, privateKey, password)
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

// encrypter is an internal helper that encrypts any string using the IBM Confidential Computing
// encryption format. It generates a random AES-256 password, encrypts the password with the
// IBM encryption certificate (RSA), encrypts the data with the password (AES-256-CBC), and
// returns the result in the format "hyper-protect-basic.<encrypted-password>.<encrypted-data>".
//
// Parameters:
//   - stringText: String data to encrypt (text, JSON, or Base64-encoded TGZ)
//   - hyperProtectOs: Target platform — "hpvs", "hpcr-rhvs", or "hpcc-peerpod" (default: hpvs)
//   - encryptionCertificate: PEM-formatted encryption certificate (optional, uses default if empty)
//
// Returns:
//   - Encrypted string in format "hyper-protect-basic.<encrypted-password>.<encrypted-data>"
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
