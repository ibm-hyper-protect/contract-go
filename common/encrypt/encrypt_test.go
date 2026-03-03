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
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	certificateUrl       = "https://hpvsvpcubuntu.s3.us.cloud-object-storage.appdomain.cloud/s390x-22/ibm-hyper-protect-container-runtime-1-0-s390x-22-encrypt.crt"
	simpleContractPath   = "../../samples/simple_contract.yaml"
	samplePrivateKeyPath = "../../samples/contract-expiry/private.pem"
	sampleCaCertPath     = "../../samples/contract-expiry/personal_ca.crt"
	sampleCaKeyPath      = "../../samples/contract-expiry/personal_ca.pem"
	sampleCsrFilePath    = "../../samples/contract-expiry/csr.pem"

	sampleCsrCountry  = "IN"
	sampleCsrState    = "Karnataka"
	sampleCsrLocation = "Bangalore"
	sampleCsrOrg      = "IBM"
	sampleCsrUnit     = "ISDL"
	sampleCsrDomain   = "HPVS"
	sampleCsrMailId   = "sashwat.k@ibm.com"

	sampleExpiryDays = 365

	simplePrivateKeyPath = "../../samples/encrypt/private.pem"
	simplePublicKeyPath  = "../../samples/encrypt/public.pem"
)

// Testcase to check if OpensslCheck() is able to check if openssl is present in the system or not
func TestOpensslCheck(t *testing.T) {
	err := OpensslCheck()
	if err != nil {
		t.Errorf("openssl check failed - %v", err)
	}
}

// Testcase to check if GeneratePublicKey() is able to generate public key
func TestGeneratePublicKey(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(simplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	publicKey, err := gen.ReadDataFromFile(simplePublicKeyPath)
	if err != nil {
		t.Errorf("failed to read public key - %v", err)
	}

	result, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Errorf("failed to generate public key - %v", err)
	}

	assert.Equal(t, result, publicKey)
}

// Testcase to check if RandomPasswordGenerator() is able to generate random password
func TestRandomPasswordGenerator(t *testing.T) {
	result, err := RandomPasswordGenerator()
	if err != nil {
		t.Errorf("failed to generate random password - %v", err)
	}

	assert.NotEmpty(t, result, "Random password did not get generated")
}

// Testcase to check if EncryptPassword() is able to encrypt password
func TestEncryptPassword(t *testing.T) {
	password, err := RandomPasswordGenerator()
	if err != nil {
		t.Errorf("failed to generate random password - %v", err)
	}

	encryptCertificate, err := gen.CertificateDownloader(certificateUrl)
	if err != nil {
		t.Errorf("failed to get encryption certificate - %v", err)
	}

	result, err := EncryptPassword(password, encryptCertificate)
	if err != nil {
		t.Errorf("failed to encrypt password - %v", err)
	}

	assert.NotEmpty(t, result, "Encrypted password did not get generated")
}

// Testcase to check if EncryptContract() is able to encrypt contract
func TestEncryptContract(t *testing.T) {
	var contractMap map[string]interface{}

	contract, err := gen.ReadDataFromFile(simpleContractPath)
	if err != nil {
		t.Errorf("failed to read contract - %v", err)
	}

	err = yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		t.Errorf("failed to unmarshal YAML - %v", err)
	}

	password, err := RandomPasswordGenerator()
	if err != nil {
		t.Errorf("failed to generate random password - %v", err)
	}

	result, err := EncryptContract(password, contractMap["workload"].(string))
	if err != nil {
		t.Errorf("failed to encrypt contract - %v", err)
	}

	assert.NotEmpty(t, result, "Encrypted workload did not get generated")
}

// Testcase to check if EncryptString() is able to encrypt string
func TestEncryptString(t *testing.T) {
	password, err := RandomPasswordGenerator()
	if err != nil {
		t.Errorf("failed to generate random password - %v", err)
	}

	contract := `
	workload: |
		type: workload
	`

	result, err := EncryptString(password, contract)
	if err != nil {
		t.Errorf("failed to encrypt string - %v", err)
	}

	assert.NotEmpty(t, result, "Encrypted workload did not get generated")
}

// Testcase to check if EncryptFinalStr() is able to generate hyper-protect-basic.<password>.<workload>
func TestEncryptFinalStr(t *testing.T) {
	var contractMap map[string]interface{}

	contract, err := gen.ReadDataFromFile(simpleContractPath)
	if err != nil {
		t.Errorf("failed to get contract - %v", err)
	}

	err = yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		t.Errorf("failed to unmarshal YAML - %v", err)
	}

	password, err := RandomPasswordGenerator()
	if err != nil {
		t.Errorf("failed to generate random password - %v", err)
	}

	encryptCertificate, err := gen.CertificateDownloader(certificateUrl)
	if err != nil {
		t.Errorf("failed to get encryption certificate - %v", err)
	}

	encryptedRandomPassword, err := EncryptPassword(password, encryptCertificate)
	if err != nil {
		t.Errorf("failed to encrypt password - %v", err)
	}

	encryptedWorkload, err := EncryptContract(password, contractMap["workload"].(string))
	if err != nil {
		t.Errorf("failed to encrypt workload - %v", err)
	}

	finalWorkload := EncryptFinalStr(encryptedRandomPassword, encryptedWorkload)

	assert.NotEmpty(t, finalWorkload, "Final workload did not get generated")
	assert.Contains(t, finalWorkload, "hyper-protect-basic.")
}

// Testcase to check if CreateSigningCert() is able to create signing certificate with CSR parameters
func TestCreateSigningCert(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to get private key - %v", err)
	}

	cacert, err := gen.ReadDataFromFile(sampleCaCertPath)
	if err != nil {
		t.Errorf("failed to get CA certificate - %v", err)
	}

	caKey, err := gen.ReadDataFromFile(sampleCaKeyPath)
	if err != nil {
		t.Errorf("failed to get CA Key - %v", err)
	}

	csrDataMap := map[string]interface{}{
		"country":  sampleCsrCountry,
		"state":    sampleCsrState,
		"location": sampleCsrLocation,
		"org":      sampleCsrOrg,
		"unit":     sampleCsrUnit,
		"domain":   sampleCsrDomain,
		"mail":     sampleCsrMailId,
	}
	csrDataStr, err := json.Marshal(csrDataMap)
	if err != nil {
		t.Errorf("failed to unmarshal JSON - %v", err)
	}

	signingCert, err := CreateSigningCert(privateKey, cacert, caKey, string(csrDataStr), "", sampleExpiryDays)
	if err != nil {
		t.Errorf("failed to create Signing certificate - %v", err)
	}

	assert.NotEmpty(t, signingCert, "Signing certificate did not get generated")
}

// Testcase to check if CreateSigningCert() is able to create signing certificate using CSR file
func TestCreateSigningCertCsrFile(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to get private key - %v", err)
	}

	cacert, err := gen.ReadDataFromFile(sampleCaCertPath)
	if err != nil {
		t.Errorf("failed to get CA certificate - %v", err)
	}

	caKey, err := gen.ReadDataFromFile(sampleCaKeyPath)
	if err != nil {
		t.Errorf("failed to get CA key - %v", err)
	}

	csr, err := gen.ReadDataFromFile(sampleCsrFilePath)
	if err != nil {
		t.Errorf("failed to get CSR file - %v", err)
	}

	signingCert, err := CreateSigningCert(privateKey, cacert, caKey, "", csr, sampleExpiryDays)
	if err != nil {
		t.Errorf("failed to create signing certificate - %v", err)
	}

	assert.NotEmpty(t, signingCert, "Signing certificate did not get generated")
}

// Testcase to check if SignContract() is able to sign the contract
func TestSignContract(t *testing.T) {
	var contractMap map[string]interface{}

	contract, err := gen.ReadDataFromFile(simpleContractPath)
	if err != nil {
		t.Errorf("failed to get contract - %v", err)
	}

	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to get private key - %v", err)
	}

	err = yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		t.Errorf("failed to unmarshal YAML - %v", err)
	}

	password, err := RandomPasswordGenerator()
	if err != nil {
		t.Errorf("failed to generate random password - %v", err)
	}

	encryptCertificate, err := gen.CertificateDownloader(certificateUrl)
	if err != nil {
		t.Errorf("failed to get encryption certificate - %v", err)
	}

	encryptedPassword, err := EncryptPassword(password, encryptCertificate)
	if err != nil {
		t.Errorf("failed to encrypt password - %v", err)
	}

	encryptedWorkload, err := EncryptContract(password, contractMap["workload"].(string))
	if err != nil {
		t.Errorf("failed to encrypt workload - %v", err)
	}
	finalWorkload := EncryptFinalStr(encryptedPassword, encryptedWorkload)

	encryptedEnv, err := EncryptContract(password, contractMap["env"].(string))
	if err != nil {
		t.Errorf("failed to encrypt env - %v", err)
	}

	finalEnv := EncryptFinalStr(encryptedPassword, encryptedEnv)

	workloadEnvSignature, err := SignContract(finalWorkload, finalEnv, privateKey)
	if err != nil {
		t.Errorf("failed to generate workload env signature - %v", err)
	}

	assert.NotEmpty(t, workloadEnvSignature, "workloadEnvSignature did not get generated")
}

// Testcase to check if GenFinalSignedContract() is able to generate signed contract
func TestGenFinalSignedContract(t *testing.T) {
	_, err := GenFinalSignedContract("test1", "test2", "test3", "")

	assert.NoError(t, err, "failed to generate final signed and encrypted contract")
}

// Testcase to check if GenFinalSignedContract() is able to generate signed contract with attestation public key
func TestGenFinalSignedContractAttest(t *testing.T) {
	_, err := GenFinalSignedContract("test1", "test2", "test3", "test4")

	assert.NoError(t, err, "failed to generate final signed and encrypted contract")
}

// Testcase to check if GeneratePublicKey() handles invalid private key
func TestGeneratePublicKeyInvalidPrivateKey(t *testing.T) {
	_, err := GeneratePublicKey("invalid-private-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute openssl command")
}

// Testcase to check if EncryptPassword() handles invalid certificate
func TestEncryptPasswordInvalidCertificate(t *testing.T) {
	_, err := EncryptPassword("password123", "invalid-certificate")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute openssl command")
}

// Testcase to check if SignContract() handles invalid private key
func TestSignContractInvalidPrivateKey(t *testing.T) {
	contract, err := gen.ReadDataFromFile(simpleContractPath)
	if err != nil {
		t.Errorf("failed to read contract - %v", err)
	}

	_, err = SignContract(contract, "", "invalid-private-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute openssl command")
}

// Testcase to check if RandomPasswordGenerator() works correctly
func TestRandomPasswordGeneratorSuccess(t *testing.T) {
	password, err := RandomPasswordGenerator()
	assert.NoError(t, err)
	assert.NotEmpty(t, password)
}

// Testcase to check if EncryptPassword() handles empty certificate
func TestEncryptPasswordEmptyCertificate(t *testing.T) {
	_, err := EncryptPassword("password123", "")
	assert.Error(t, err)
}

// Testcase to check if CreateSigningCert() handles invalid CA certificate
func TestCreateSigningCertInvalidCaCert(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	caKey, err := gen.ReadDataFromFile(sampleCaKeyPath)
	if err != nil {
		t.Errorf("failed to read CA key - %v", err)
	}

	csrParams := map[string]interface{}{
		"country":  sampleCsrCountry,
		"state":    sampleCsrState,
		"location": sampleCsrLocation,
		"org":      sampleCsrOrg,
		"unit":     sampleCsrUnit,
		"domain":   sampleCsrDomain,
		"mail":     sampleCsrMailId,
	}

	csrParamsJson, _ := json.Marshal(csrParams)

	_, err = CreateSigningCert(privateKey, "invalid-ca-cert", caKey, string(csrParamsJson), "", sampleExpiryDays)
	assert.Error(t, err)
}

// Testcase to check if CreateSigningCert() handles invalid CA key
func TestCreateSigningCertInvalidCaKey(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	caCert, err := gen.ReadDataFromFile(sampleCaCertPath)
	if err != nil {
		t.Errorf("failed to read CA certificate - %v", err)
	}

	csrParams := map[string]interface{}{
		"country":  sampleCsrCountry,
		"state":    sampleCsrState,
		"location": sampleCsrLocation,
		"org":      sampleCsrOrg,
		"unit":     sampleCsrUnit,
		"domain":   sampleCsrDomain,
		"mail":     sampleCsrMailId,
	}

	csrParamsJson, _ := json.Marshal(csrParams)

	_, err = CreateSigningCert(privateKey, caCert, "invalid-ca-key", string(csrParamsJson), "", sampleExpiryDays)
	assert.Error(t, err)
}

// Testcase to check if CreateCert() handles invalid private key
func TestCreateCertInvalidPrivateKey(t *testing.T) {
	csrParams := map[string]interface{}{
		"country":  sampleCsrCountry,
		"state":    sampleCsrState,
		"location": sampleCsrLocation,
		"org":      sampleCsrOrg,
		"unit":     sampleCsrUnit,
		"domain":   sampleCsrDomain,
		"mail":     sampleCsrMailId,
	}

	csrParamsJson, _ := json.Marshal(csrParams)

	_, err := CreateCert("invalid-private-key", string(csrParamsJson), "", sampleExpiryDays)
	assert.Error(t, err)
}

// Testcase to check if EncryptContract() works correctly
func TestEncryptContractSuccess(t *testing.T) {
	password := "testpassword123"
	contract := "test contract data"

	result, err := EncryptContract(password, contract)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if EncryptFinalStr() works correctly
func TestEncryptFinalStrSuccess(t *testing.T) {
	encryptedPassword := "encryptedpass"
	encryptedContract := "encryptedcontract"

	result := EncryptFinalStr(encryptedPassword, encryptedContract)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "hyper-protect-basic")
	assert.Contains(t, result, encryptedPassword)
	assert.Contains(t, result, encryptedContract)
}

// Testcase to check if EncryptString() works with valid inputs
func TestEncryptStringValidInputs(t *testing.T) {
	password := "testpassword123"
	section := "test section data"

	result, err := EncryptString(password, section)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if OpensslCheck() works correctly
func TestOpensslCheckSuccess(t *testing.T) {
	err := OpensslCheck()
	assert.NoError(t, err)
}

// Testcase to check if EncryptString() handles empty password
func TestEncryptStringEmptyPassword(t *testing.T) {
	section := "test section data"

	_, err := EncryptString("", section)
	// Empty password causes OpenSSL to fail
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to execute openssl command")
}

// Testcase to check if EncryptString() handles empty section
func TestEncryptStringEmptySection(t *testing.T) {
	password := "testpassword123"

	result, err := EncryptString(password, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if EncryptPassword() handles empty password
func TestEncryptPasswordEmptyPassword(t *testing.T) {
	encryptCertificate, err := gen.CertificateDownloader(certificateUrl)
	if err != nil {
		t.Errorf("failed to get encryption certificate - %v", err)
	}

	result, err := EncryptPassword("", encryptCertificate)
	// Empty password is valid for RSA encryption
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if SignContract() handles empty workload
func TestSignContractEmptyWorkload(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	result, err := SignContract("", "test-env", privateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if SignContract() handles empty env
func TestSignContractEmptyEnv(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	result, err := SignContract("test-workload", "", privateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if SignContract() handles empty private key
func TestSignContractEmptyPrivateKey(t *testing.T) {
	_, err := SignContract("test-workload", "test-env", "")
	assert.Error(t, err)
}

// Testcase to check if CreateSigningCert() handles invalid JSON in csrData
func TestCreateSigningCertInvalidJSON(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	cacert, err := gen.ReadDataFromFile(sampleCaCertPath)
	if err != nil {
		t.Errorf("failed to read CA certificate - %v", err)
	}

	caKey, err := gen.ReadDataFromFile(sampleCaKeyPath)
	if err != nil {
		t.Errorf("failed to read CA key - %v", err)
	}

	_, err = CreateSigningCert(privateKey, cacert, caKey, "invalid-json", "", sampleExpiryDays)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal JSON")
}

// Testcase to check if CreateSigningCert() handles invalid private key
func TestCreateSigningCertInvalidPrivateKey(t *testing.T) {
	cacert, err := gen.ReadDataFromFile(sampleCaCertPath)
	if err != nil {
		t.Errorf("failed to read CA certificate - %v", err)
	}

	caKey, err := gen.ReadDataFromFile(sampleCaKeyPath)
	if err != nil {
		t.Errorf("failed to read CA key - %v", err)
	}

	csrParams := map[string]interface{}{
		"country":  sampleCsrCountry,
		"state":    sampleCsrState,
		"location": sampleCsrLocation,
		"org":      sampleCsrOrg,
		"unit":     sampleCsrUnit,
		"domain":   sampleCsrDomain,
		"mail":     sampleCsrMailId,
	}

	csrParamsJson, _ := json.Marshal(csrParams)

	_, err = CreateSigningCert("invalid-private-key", cacert, caKey, string(csrParamsJson), "", sampleExpiryDays)
	assert.Error(t, err)
}

// Testcase to check if CreateSigningCert() handles invalid CSR PEM data
func TestCreateSigningCertInvalidCsrPem(t *testing.T) {
	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to read private key - %v", err)
	}

	cacert, err := gen.ReadDataFromFile(sampleCaCertPath)
	if err != nil {
		t.Errorf("failed to read CA certificate - %v", err)
	}

	caKey, err := gen.ReadDataFromFile(sampleCaKeyPath)
	if err != nil {
		t.Errorf("failed to read CA key - %v", err)
	}

	_, err = CreateSigningCert(privateKey, cacert, caKey, "", "invalid-csr-pem", sampleExpiryDays)
	assert.Error(t, err)
}

// Testcase to check if GenFinalSignedContract() handles empty workload
func TestGenFinalSignedContractEmptyWorkload(t *testing.T) {
	result, err := GenFinalSignedContract("", "test-env", "test-signature", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if GenFinalSignedContract() handles empty env
func TestGenFinalSignedContractEmptyEnv(t *testing.T) {
	result, err := GenFinalSignedContract("test-workload", "", "test-signature", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if GenFinalSignedContract() handles empty signature
func TestGenFinalSignedContractEmptySignature(t *testing.T) {
	result, err := GenFinalSignedContract("test-workload", "test-env", "", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if EncryptContract() handles empty password
func TestEncryptContractEmptyPassword(t *testing.T) {
	contract := "test contract data"

	_, err := EncryptContract("", contract)
	assert.Error(t, err)
}

// Testcase to check if EncryptContract() handles empty contract
func TestEncryptContractEmptyContract(t *testing.T) {
	password := "testpassword123"

	result, err := EncryptContract(password, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// Testcase to check if GeneratePublicKey() handles empty private key
func TestGeneratePublicKeyEmptyPrivateKey(t *testing.T) {
	_, err := GeneratePublicKey("")
	assert.Error(t, err)
}

// Testcase to check if ExtractPublicKeyFromCert() is able to extract public key from certificate
func TestExtractPublicKeyFromCert(t *testing.T) {
	cacert, err := gen.ReadDataFromFile(sampleCaCertPath)
	if err != nil {
		t.Errorf("failed to get CA certificate - %v", err)
	}

	publicKey, err := ExtractPublicKeyFromCert(cacert)
	if err != nil {
		t.Errorf("failed to extract public key from certificate - %v", err)
	}

	assert.NotEmpty(t, publicKey, "Public key did not get extracted")
	assert.Contains(t, publicKey, "BEGIN PUBLIC KEY")
	assert.Contains(t, publicKey, "END PUBLIC KEY")
}

// Testcase to check if VerifySignature() is able to verify signature
func TestVerifySignature(t *testing.T) {
	// Create test data
	testData := "test data for signature verification"

	// Read private key to create signature
	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to get private key - %v", err)
	}

	// Create signature using OpenSSL
	privateKeyPath, err := gen.CreateTempFile(privateKey)
	if err != nil {
		t.Errorf("failed to create temp file - %v", err)
	}

	signature, err := gen.ExecCommand(gen.GetOpenSSLPath(), testData, "dgst", "-sha256", "-sign", privateKeyPath)
	if err != nil {
		t.Errorf("failed to create signature - %v", err)
	}

	err = gen.RemoveTempFile(privateKeyPath)
	if err != nil {
		t.Errorf("failed to remove temp file - %v", err)
	}

	// Generate public key from private key
	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Errorf("failed to generate public key - %v", err)
	}

	// Verify signature
	err = VerifySignature(testData, []byte(signature), publicKey)
	if err != nil {
		t.Errorf("signature verification failed - %v", err)
	}
}

// Testcase to check if VerifySignature() fails with invalid signature
func TestVerifySignature_InvalidSignature(t *testing.T) {
	testData := "test data"
	invalidSignature := []byte("invalid signature")

	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		t.Errorf("failed to get private key - %v", err)
	}

	publicKey, err := GeneratePublicKey(privateKey)
	if err != nil {
		t.Errorf("failed to generate public key - %v", err)
	}

	err = VerifySignature(testData, invalidSignature, publicKey)
	assert.Error(t, err, "Expected verification to fail with invalid signature")
}
