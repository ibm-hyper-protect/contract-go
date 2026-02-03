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
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	hpcrEncryptPrefix = "hyper-protect-basic."

	sampleStringData     = "sashwatk"
	sampleBase64Data     = "c2FzaHdhdGs="
	sampleInputChecksum  = "05fb716cba07a0cdda231f1aa19621ce9e183a4fb6e650b459bc3c5db7593e42"
	sampleOutputChecksum = "5fc9d046c6bb76741f2bd3029225955903727460c1da088bf9f0d93d17eaec69"

	sampleStringJson = `
	{
		"type": "env"
	}
	`
	sampleBase64Json         = "Cgl7CgkJInR5cGUiOiAiZW52IgoJfQoJ"
	sampleInputChecksumJson  = "f932f8ad556280f232f4b42d55b24ce7d2e909d3195ef60d49e92d49b735de2b"
	sampleOutputChecksumJson = "0e282874a193587be1d2aca98083e9ebbddc840edc964a130a215bd674f8487e"

	sampleComposeFolderPath     = "../samples/tgz"
	sampleComposeFolderChecksum = "3e4a006b9422a3fbf8c58d4f1dbac4494b34f800ddbb6e048c31709bb0cde599"

	simpleContractPath          = "../samples/simple_contract.yaml"
	simpleContractInputChecksum = "7ef5b4c59544adc2ccdf86432ae0f652907009d0fe759743a0771a75bf88941c"

	attestPubKeyContractPath          = "../samples/attest_pub_key_contract.yaml"
	attestPubKeyContractInputChecksum = "67fb401db11bae9bd74abf71da5d1e52ccc9b20980d7b6b0f0cf64af26db638d"

	samplePrivateKeyPath = "../samples/encrypt/private.pem"
	samplePublicKeyPath  = "../samples/encrypt/public.pem"

	sampleCePrivateKeyPath   = "../samples/contract-expiry/private.pem"
	sampleCeCaCertPath       = "../samples/contract-expiry/personal_ca.crt"
	sampleCeCaKeyPath        = "../samples/contract-expiry/personal_ca.pem"
	sampleCeCsrPath          = "../samples/contract-expiry/csr.pem"
	sampleContractExpiryDays = 365

	sampleHyperProtectOsVersion = "hpvs"

	// HPCC Initdata
	sampleSignedEncryptedContract              = "../samples/hpcc/signed-encrypt-hpcc.yaml"
	sampleGzippedInidata                       = "../samples/hpcc/gzipped-initdata"
	sampleSingedEncryptedContractInputChecksum = "1b6ee574d6061896c23fad0711d1a89b8d9b7748506ab089201db1335605daea"
)

var (
	sampleCeCSRPems = map[string]interface{}{
		"country":  "IN",
		"state":    "Karnataka",
		"location": "Bangalore",
		"org":      "IBM",
		"unit":     "ISDL",
		"domain":   "HPVS",
		"mail":     "sashwat.k@ibm.com",
	}
)

// common - common function to pull data from files
func common(testType string) (string, string, string, string, string, error) {
	var contract string
	var err error

	if testType == "TestEncryptWrapperAttestPubKey" {
		contract, err = gen.ReadDataFromFile(attestPubKeyContractPath)
		if err != nil {
			return "", "", "", "", "", err
		}
	} else {
		contract, err = gen.ReadDataFromFile(simpleContractPath)
		if err != nil {
			return "", "", "", "", "", err
		}
	}

	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		return "", "", "", "", "", err
	}

	if testType == "TestHpcrVerifyContract" {
		return contract, "", "", "", "", nil
	} else if testType == "TestHpcrContractSignedEncrypted" {
		return contract, privateKey, "", "", "", nil
	} else if testType == "TestEncryptWrapper" || testType == "TestEncryptWrapperAttestPubKey" {
		publicKey, err := gen.ReadDataFromFile(samplePublicKeyPath)
		if err != nil {
			return "", "", "", "", "", err
		}

		return contract, privateKey, publicKey, "", "", nil
	} else if testType == "TestHpcrContractSignedEncryptedContractExpiryCsrParams" || testType == "TestHpcrContractSignedEncryptedContractExpiryCsrPem" {
		cePrivateKey, err := gen.ReadDataFromFile(sampleCePrivateKeyPath)
		if err != nil {
			return "", "", "", "", "", err
		}

		caCert, err := gen.ReadDataFromFile(sampleCeCaCertPath)
		if err != nil {
			return "", "", "", "", "", err
		}

		caKey, err := gen.ReadDataFromFile(sampleCeCaKeyPath)
		if err != nil {
			return "", "", "", "", "", err
		}

		return contract, cePrivateKey, "", caCert, caKey, err
	}
	return "", "", "", "", "", err
}

// Testcase to check if TestHpcrText() is able to encode text and generate SHA256
func TestHpcrText(t *testing.T) {
	base64, inputSha256, outputSha256, err := HpcrText(sampleStringData)
	if err != nil {
		t.Errorf("failed to generate HPCR text - %v", err)
	}

	assert.Equal(t, base64, sampleBase64Data)
	assert.Equal(t, inputSha256, sampleInputChecksum)
	assert.Equal(t, outputSha256, sampleOutputChecksum)
}

// Testcase to check if HpcrJson() is able to encode JSON and generate SHA256
func TestHpcrJson(t *testing.T) {
	base64, inputSha256, outputSha256, err := HpcrJson(sampleStringJson)
	if err != nil {
		t.Errorf("failed to generate HPCR JSON - %v", err)
	}

	assert.Equal(t, base64, sampleBase64Json)
	assert.Equal(t, inputSha256, sampleInputChecksumJson)
	assert.Equal(t, outputSha256, sampleOutputChecksumJson)
}

// Testcase to check if TestHpcrTextEncrypted() is able to encrypt text and generate SHA256
func TestHpcrTextEncrypted(t *testing.T) {
	result, inputSha256, _, err := HpcrTextEncrypted(sampleStringData, sampleHyperProtectOsVersion, "")
	if err != nil {
		t.Errorf("failed to generate HPCR encrypted text - %v", err)
	}

	assert.Contains(t, result, hpcrEncryptPrefix)
	assert.Equal(t, inputSha256, sampleInputChecksum)
}

// Testcase to check if TestHpcrJsonEncrypted() is able to encrypt JSON and generate SHA256
func TestHpcrJsonEncrypted(t *testing.T) {
	result, inputSha256, _, err := HpcrJsonEncrypted(sampleStringJson, sampleHyperProtectOsVersion, "")
	if err != nil {
		t.Errorf("failed to generate HPCR encrypted JSON - %v", err)
	}

	assert.Contains(t, result, hpcrEncryptPrefix)
	assert.Equal(t, inputSha256, sampleInputChecksumJson)
}

// Testcase to check if HpcrTgz() is able to generate base64 of tar.tgz
func TestHpcrTgz(t *testing.T) {
	result, inputSha256, _, err := HpcrTgz(sampleComposeFolderPath)
	if err != nil {
		t.Errorf("failed to generate HPCR TGZ - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Equal(t, inputSha256, sampleComposeFolderChecksum)
}

// Testcase to check if HpcrTgzEncrypted() is able to generate encrypted base64 of tar.tgz
func TestHpcrTgzEncrypted(t *testing.T) {
	result, inputSha256, _, err := HpcrTgzEncrypted(sampleComposeFolderPath, sampleHyperProtectOsVersion, "")
	if err != nil {
		t.Errorf("failed to generated HPCR encrypted TGZ - %v", err)
	}

	assert.Contains(t, result, hpcrEncryptPrefix)
	assert.Equal(t, inputSha256, sampleComposeFolderChecksum)
}

// Testcase to check if HpcrVerifyContract() is able to verify contract
func TestHpcrVerifyContract(t *testing.T) {
	contract, _, _, _, _, err := common(t.Name())
	if err != nil {
		t.Errorf("failed to get contract - %v", err)
	}

	err = HpcrVerifyContract(contract, "")
	if err != nil {
		t.Errorf("failed to verify contract schema - %v", err)
	}
}

// Testcase to check if HpcrContractSignedEncrypted() is able to generate
func TestHpcrContractSignedEncrypted(t *testing.T) {
	encryption_cert := "../encryption/ibm-hyper-protect-container-runtime-1-0-s390x-25-encrypt.crt"
	data, err := os.ReadFile(encryption_cert)
	if err != nil {
		t.Errorf("Error reading file: - %v", err)
	}
	contract, privateKey, _, _, _, err := common(t.Name())
	if err != nil {
		t.Errorf("failed to get contract and private key - %v", err)
	}

	result, inputSha256, _, err := HpcrContractSignedEncrypted(contract, sampleHyperProtectOsVersion, string(data), privateKey)
	if err != nil {
		t.Errorf("failed to generate signed and encrypted contract - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Equal(t, inputSha256, simpleContractInputChecksum)
}

// Testcase to check if HpcrContractSignedEncryptedContractExpiry() is able to create signed and encrypted contract with contract expiry enabled with CSR parameters
func TestHpcrContractSignedEncryptedContractExpiryCsrParams(t *testing.T) {
	contract, privateKey, _, caCert, caKey, err := common(t.Name())
	if err != nil {
		t.Errorf("failed to get contract, private key, CA certificate and CA key - %v", err)
	}

	csrParams, err := json.Marshal(sampleCeCSRPems)
	if err != nil {
		t.Errorf("failed to unmarshal CSR parameters - %v", err)
	}

	result, inputSha256, _, err := HpcrContractSignedEncryptedContractExpiry(contract, sampleHyperProtectOsVersion, "", privateKey, caCert, caKey, string(csrParams), "", sampleContractExpiryDays)
	if err != nil {
		t.Errorf("failed to generate signed and encrypted contract with contract expiry - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Equal(t, inputSha256, simpleContractInputChecksum)
}

// Testcase to check if HpcrContractSignedEncryptedContractExpiry() is able to create signed and encrypted contract with contract expiry enabled with CSR PEM data
func TestHpcrContractSignedEncryptedContractExpiryCsrPem(t *testing.T) {
	contract, privateKey, _, caCert, caKey, err := common(t.Name())
	if err != nil {
		t.Errorf("failed to get contract, private key, CA certificate and CA key - %v", err)
	}

	csr, err := gen.ReadDataFromFile(sampleCeCsrPath)
	if err != nil {
		t.Errorf("failed to read CSR file - %v", err)
	}

	result, inputSha256, _, err := HpcrContractSignedEncryptedContractExpiry(contract, sampleHyperProtectOsVersion, "", privateKey, caCert, caKey, "", csr, sampleContractExpiryDays)
	if err != nil {
		t.Errorf("failed to generate signed and encrypted contract with contract expiry - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Equal(t, inputSha256, simpleContractInputChecksum)
}

// Testcase to check if encryptWrapper() is able to sign and encrypt a contract
func TestEncryptWrapper(t *testing.T) {
	contract, privateKey, publicKey, _, _, err := common("TestEncryptWrapper")
	if err != nil {
		t.Errorf("failed to get contract, private key and public key - %v", err)
	}

	result, err := encryptWrapper(contract, sampleHyperProtectOsVersion, "", privateKey, publicKey)
	if err != nil {
		t.Errorf("failed to sign and encrypt contract - %v", err)
	}

	assert.NotEmpty(t, result)
}

// Testcase to check if encryptWrapper() is able to sign and encrypt a contract with attestation public key
func TestEncryptWrapperAttestPubKey(t *testing.T) {
	contract, privateKey, publicKey, _, _, err := common("TestEncryptWrapperAttestPubKey")
	if err != nil {
		t.Errorf("failed to get contract, private key and public key - %v", err)
	}

	result, err := encryptWrapper(contract, sampleHyperProtectOsVersion, "", privateKey, publicKey)
	if err != nil {
		t.Errorf("failed to sign and encrypt contract - %v", err)
	}

	fmt.Println(result)

	assert.NotEmpty(t, result)
}

// Testcase to check if encrypter() is able to encrypt and generate SHA256 from string
func TestEncrypter(t *testing.T) {
	result, err := encrypter(sampleStringJson, sampleHyperProtectOsVersion, "")
	if err != nil {
		t.Errorf("failed to encrypt contract - %v", err)
	}

	assert.Contains(t, result, hpcrEncryptPrefix)
}

// Testcase to check HpccInitdata() is able to gzip data.
func TestHpccInitdata(t *testing.T) {
	if !gen.CheckFileFolderExists(sampleSignedEncryptedContract) {
		t.Errorf("failed, file does not exits on defined path")
	}

	inputData, err := gen.ReadDataFromFile(sampleSignedEncryptedContract)
	if err != nil {
		t.Errorf("failed to read content from encrypted contract - %v", err)
	}

	encodedString, inputCheckSum, _, err := HpccInitdata(inputData)
	if err != nil {
		t.Errorf("failed to gzipped encoded initdata - %v", err)
	}

	expectedGzippedInitdata, err := gen.ReadDataFromFile(sampleGzippedInidata)
	if err != nil {
		t.Errorf("failed to read gzipped-initdata file - %v", err)
	}

	assert.Equal(t, expectedGzippedInitdata, encodedString, "Encoded gzipped initdata string does not match with expected gzipped initdata")
	assert.Equal(t, sampleSingedEncryptedContractInputChecksum, inputCheckSum, "Checksum does not match with expected input checksum of encrypted contract")
}

// Testcase to check HpccInitdata() is able to handle empty contract case.
func TestHpccInitdataEmptyContract(t *testing.T) {
	_, _, _, err := HpccInitdata("")
	assert.EqualError(t, err, emptyParameterErrStatement)
}
