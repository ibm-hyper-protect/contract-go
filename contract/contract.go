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
	"fmt"

	"gopkg.in/yaml.v3"

	enc "github.com/ibm-hyper-protect/contract-go/common/encrypt"
	gen "github.com/ibm-hyper-protect/contract-go/common/general"
)

const (
	emptyParameterErrStatement = "required parameter is empty"
)

// HpcrText - function to generate base64 data and checksum from string
func HpcrText(plainText string) (string, string, string, error) {
	if gen.CheckIfEmpty(plainText) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	hpcrTextStr := gen.EncodeToBase64([]byte(plainText))

	return hpcrTextStr, gen.GenerateSha256(plainText), gen.GenerateSha256(hpcrTextStr), nil
}

// HpcrJson - function to generate base64 data and checksum from JSON string
func HpcrJson(plainJson string) (string, string, string, error) {
	if !gen.IsJSON(plainJson) {
		return "", "", "", fmt.Errorf("not a JSON data")
	}

	hpcrJsonStr := gen.EncodeToBase64([]byte(plainJson))

	return hpcrJsonStr, gen.GenerateSha256(plainJson), gen.GenerateSha256(hpcrJsonStr), nil
}

// HpcrTextEncrypted - function to generate encrypted Hyper protect data and SHA256 from plain text
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

// HpcrJsonEncrypted - function to generate encrypted hyper protect data and SHA256 from plain JSON data
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

// HpcrTgz - function to generate base64 of tar.tgz which was prepared from docker compose/podman files
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

// HpcrTgzEncrypted - function to generate encrypted tgz
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

// HpcrVerifyContract - function to verify contract schema
func HpcrVerifyContract(contract, version string) error {
	return gen.VerifyContractWithSchema(contract, version)
}

// HpcrContractSignedEncrypted - function to generate Signed and Encrypted contract
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

	status, err := gen.CheckEncryptionCertValidityForContractEncryption(encryptionCertificate)
	if err != nil {
		return "", "", "", fmt.Errorf("Failed to encrypt contract - %v", err)
	}

	fmt.Println("Encryption Certificate validity status - ", status)

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

// HpcrContractSignedEncryptedContractExpiry - function to generate sign with contract expiry enabled and encrypt contract (with CSR parameters and CSR file)
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

// encryptWrapper - wrapper function to sign (with and without contract expiry) and encrypt contract
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

	finalContract, err := enc.GenFinalSignedContract(encryptedWorkload, encryptedEnv, workloadEnvSignature)
	if err != nil {
		return "", fmt.Errorf("failed to generate final contract - %v", err)
	}

	return finalContract, nil
}

// encrypter - function to generate encrypted hyper protect data from plain string
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
