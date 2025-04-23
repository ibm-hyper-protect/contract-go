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

	hpcrTextStr := gen.EncodeToBase64(plainText)

	return hpcrTextStr, gen.GenerateSha256(plainText), gen.GenerateSha256(hpcrTextStr), nil
}

// HpcrJson - function to generate base64 data and checksum from JSON string
func HpcrJson(plainJson string) (string, string, string, error) {
	if !gen.IsJSON(plainJson) {
		return "", "", "", fmt.Errorf("not a JSON data")
	}

	hpcrJsonStr := gen.EncodeToBase64(plainJson)

	return hpcrJsonStr, gen.GenerateSha256(plainJson), gen.GenerateSha256(hpcrJsonStr), nil
}

// HpcrTextEncrypted - function to generate encrypted Hyper protect data and SHA256 from plain text
func HpcrTextEncrypted(plainText, hyperProtectOs, encryptionCertificate string) (string, string, string, error) {
	if gen.CheckIfEmpty(plainText) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	hpcrTextEncryptedStr, err := Encrypter(plainText, hyperProtectOs, encryptionCertificate)
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

	hpcrJsonEncrypted, err := Encrypter(plainJson, hyperProtectOs, encryptionCertificate)
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

	hpcrTgzEncryptedStr, err := Encrypter(tgzBase64, hyperProtectOs, encryptionCertificate)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate encrypted tgz - %v", err)
	}

	return hpcrTgzEncryptedStr, gen.GenerateSha256(folderPath), gen.GenerateSha256(hpcrTgzEncryptedStr), nil
}

// HpcrContractSignedEncrypted - function to generate Signed and Encrypted contract
func HpcrContractSignedEncrypted(contract, hyperProtectOs, encryptionCertificate, privateKey string) (string, string, string, error) {
	err := gen.VerifyContractWithSchema(contract)
	if err != nil {
		return "", "", "", fmt.Errorf("schema verification failed - %v", err)
	}

	if gen.CheckIfEmpty(contract, privateKey) {
		return "", "", "", fmt.Errorf(emptyParameterErrStatement)
	}

	encryptCertificate := gen.FetchEncryptionCertificate(hyperProtectOs, encryptionCertificate)

	publicKey, err := enc.GeneratePublicKey(privateKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate public key - %v", err)
	}

	signedEncryptContract, err := EncryptWrapper(contract, hyperProtectOs, encryptCertificate, privateKey, publicKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to sign and encrypt contract - %v", err)
	}

	return signedEncryptContract, gen.GenerateSha256(contract), gen.GenerateSha256(signedEncryptContract), nil
}

// HpcrContractSignedEncryptedContractExpiry - function to generate sign with contract expiry enabled and encrypt contract (with CSR parameters and CSR file)
func HpcrContractSignedEncryptedContractExpiry(contract, hyperProtectOs, encryptionCertificate, privateKey, cacert, caKey, csrDataStr, csrPemData string, expiryDays int) (string, string, string, error) {
	err := gen.VerifyContractWithSchema(contract)
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

	finalContract, err := EncryptWrapper(contract, hyperProtectOs, encryptionCertificate, privateKey, signingCert)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate signed and encrypted contract - %v", err)
	}

	return finalContract, gen.GenerateSha256(contract), gen.GenerateSha256(finalContract), nil
}

// EncryptWrapper - wrapper function to sign (with and without contract expiry) and encrypt contract
func EncryptWrapper(contract, hyperProtectOs, encryptionCertificate, privateKey, publicKey string) (string, error) {
	if gen.CheckIfEmpty(contract, privateKey, publicKey) {
		return "", fmt.Errorf(emptyParameterErrStatement)
	}

	var contractMap map[string]interface{}

	encryptCertificate := gen.FetchEncryptionCertificate(hyperProtectOs, encryptionCertificate)

	err := yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal YAML - %v", err)
	}

	workloadData, err := gen.MapToYaml(contractMap["workload"].(map[string]interface{}))
	if err != nil {
		return "", fmt.Errorf("failed to convert MAP to YAML - %v", err)
	}

	encryptedWorkload, err := Encrypter(workloadData, hyperProtectOs, encryptCertificate)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt workload - %v", err)
	}

	updatedEnv, err := gen.KeyValueInjector(contractMap["env"].(map[string]interface{}), "signingKey", gen.EncodeToBase64(publicKey))
	if err != nil {
		return "", fmt.Errorf("failed to inject signingKey to env - %v", err)
	}

	encryptedEnv, err := Encrypter(updatedEnv, hyperProtectOs, encryptCertificate)
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

// Encrypter - function to generate encrypted hyper protect data from plain string
func Encrypter(stringText, hyperProtectOs, encryptionCertificate string) (string, error) {
	if gen.CheckIfEmpty(stringText) {
		return "", fmt.Errorf(emptyParameterErrStatement)
	}

	encCert := gen.FetchEncryptionCertificate(hyperProtectOs, encryptionCertificate)

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
