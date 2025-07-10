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

package general

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	cert "github.com/ibm-hyper-protect/contract-go/encryption"
)

const (
	simpleSampleText     = "Testing"
	simpleSampleTextPath = "../../samples/simple_file.txt"

	simpleContractPath        = "../../samples/simple_contract.yaml"
	simpleInvalidContractPath = "../../samples/simple_contract_invalid.yaml"

	simpleWorkloadPath = "../../samples/workload.yaml"

	certificateDownloadUrl = "https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-15-encrypt.crt"

	sampleStringData   = "sashwatk"
	sampleBase64Data   = "c2FzaHdhdGs="
	sampleDataChecksum = "05fb716cba07a0cdda231f1aa19621ce9e183a4fb6e650b459bc3c5db7593e42"

	sampleCertificateJson = `{
		"1.0.0": "data1",
		"1.2.5": "data2",
		"2.0.5": "data3",
		"3.5.10": "data4",
		"4.0.0": "data5"
	}`

	sampleComposeFolder = "../../samples/tgz"
)

// Testcase to check if CheckIfEmpty() is able to identify empty variables
func TestCheckIfEmpty(t *testing.T) {
	result := CheckIfEmpty("")

	assert.True(t, result)
}

// Testcase to check ExecCommand() works
func TestExecCommand(t *testing.T) {
	_, err := ExecCommand("openssl", "", "version")
	if err != nil {
		t.Errorf("failed to execute command - %v", err)
	}
}

// Testcase to check ExecCommand() when user input is given
func TestExecCommandUserInput(t *testing.T) {
	_, err := ExecCommand("openssl", "hello", "version")
	if err != nil {
		t.Errorf("failed to execute command - %v", err)
	}
}

// Testcase to check if ReadDataFromFile() can read data from file
func TestReadDataFromFile(t *testing.T) {
	content, err := ReadDataFromFile(simpleSampleTextPath)
	if err != nil {
		t.Errorf("failed to read text from file - %v", err)
	}

	assert.Equal(t, content, simpleSampleText)
}

// Testcase to check if CreateTempFile() can create and modify temp files
func TestCreateTempFile(t *testing.T) {
	tmpfile, err := CreateTempFile(simpleSampleText)
	if err != nil {
		t.Errorf("failed to create temp file - %v", err)
	}

	content, err := ReadDataFromFile(tmpfile)
	if err != nil {
		t.Errorf("failed to read data from file - %v", err)
	}

	err = RemoveTempFile(tmpfile)
	if err != nil {
		t.Errorf("failed to remove file - %v", err)
	}

	assert.Equal(t, simpleSampleText, content)
}

// Testcase to check TestRemoveTempFile() removes a file
func TestRemoveTempFile(t *testing.T) {
	tmpfile, err := CreateTempFile(simpleSampleText)
	if err != nil {
		t.Errorf("failed to create temp file - %v", err)
	}

	err = RemoveTempFile(tmpfile)
	if err != nil {
		t.Errorf("failed to remove file - %v", err)
	}

	err1 := CheckFileFolderExists(tmpfile)

	assert.False(t, err1, "The created file was removed and must not exist")
}

// Testcase to check if ListFoldersAndFiles() is able to list files and folders under a folder
func TestListFoldersAndFiles(t *testing.T) {
	result, err := ListFoldersAndFiles(sampleComposeFolder)
	if err != nil {
		t.Errorf("failed to list files and folders - %v", err)
	}

	assert.Contains(t, result, filepath.Join(sampleComposeFolder, "docker-compose.yaml"))
}

// Testcase to check if CheckFileFolderExists() is able check if file or folder exists
func TestCheckFileFolderExists(t *testing.T) {
	result := CheckFileFolderExists(sampleComposeFolder)

	assert.True(t, result)
}

// Testcase to check if IsJSON() is able to check if input data is JSON or not
func TestIsJson(t *testing.T) {
	result := IsJSON(sampleCertificateJson)

	assert.Equal(t, result, true)
}

// Testcase to check if EncodeToBase64() can encode string to base64
func TestEncodeToBase64(t *testing.T) {
	result := EncodeToBase64([]byte(sampleStringData))

	assert.Equal(t, result, sampleBase64Data)
}

// Testcase to check if DecodeBase64String() can decode base64 string
func TestDecodeBase64String(t *testing.T) {
	result, err := DecodeBase64String(sampleBase64Data)
	if err != nil {
		t.Errorf("failed to decode Base64 string - %v", err)
	}

	assert.Equal(t, sampleStringData, result)
}

// Testcase to check if GenerateSha256() is able to generate SHA256 of string
func TestGenerateSha256(t *testing.T) {
	result := GenerateSha256(sampleStringData)

	assert.NotEmpty(t, result)
}

// Testcase to check if MapToYaml() can convert Map to YAML string
func TestMapToYaml(t *testing.T) {
	var workloadMap map[string]interface{}

	workload, err := ReadDataFromFile(simpleWorkloadPath)
	if err != nil {
		t.Errorf("failed to read contract - %v", err)
	}

	err = yaml.Unmarshal([]byte(workload), &workloadMap)
	if err != nil {
		t.Errorf("failed to unmarshal YAML - %v", err)
	}

	_, err = MapToYaml(workloadMap["compose"].(map[string]interface{}))
	if err != nil {
		t.Errorf("failed to convert MAP to YAML - %v", err)
	}
}

// Testcase to check if KeyValueInjector() can add key value to existing map
func TestKeyValueInjector(t *testing.T) {
	key := "envWorkloadSignature"
	value := "testing123"

	contract, err := ReadDataFromFile(simpleContractPath)
	if err != nil {
		t.Errorf("failed to read contract - %v", err)
	}

	finalContract, err := KeyValueInjector(contract, key, value)
	if err != nil {
		t.Errorf("failed to inject envWorkloadSignature - %v", err)
	}

	assert.Contains(t, finalContract, fmt.Sprintf("%s: %s", key, value))
}

// Testcase to check if CertificateDownloader() can download encryption certificate
func TestCertificateDownloader(t *testing.T) {
	certificate, err := CertificateDownloader(certificateDownloadUrl)
	if err != nil {
		t.Errorf("failed to download certificate - %v", err)
	}

	assert.Contains(t, certificate, "-----BEGIN CERTIFICATE-----")
}

// Testcase to check if GetEncryptPassWorkload() can fetch encoded encrypted password and encoded encrypted data from string
func TestGetEncryptPassWorkload(t *testing.T) {
	encryptedData := "hyper-protect-basic.sashwat.k"

	a, b := GetEncryptPassWorkload(encryptedData)

	assert.Equal(t, a, "sashwat")
	assert.Equal(t, b, "k")
}

// Testcase to check if CheckUrlExists() is able to validate URL
func TestCheckUrlExists(t *testing.T) {
	result, err := CheckUrlExists(certificateDownloadUrl)
	if err != nil {
		t.Errorf("URL verification failed - %v", err)
	}

	assert.Equal(t, result, true)
}

// Testcase to check if GetDataFromLatestVersion() is able to fetch latest version of encryption certificate
func TestGetDataFromLatestVersion(t *testing.T) {
	versionConstraints := ">= 1.0.0, <= 3.5.10"

	key, value, err := GetDataFromLatestVersion(sampleCertificateJson, versionConstraints)
	if err != nil {
		t.Errorf("failed to get encryption certificate - %v", err)
	}

	assert.Equal(t, key, "3.5.10")
	assert.Equal(t, value, "data4")
}

// Testcase to check if FetchEncryptionCertificate() fetches encryption certificate
func TestFetchEncryptionCertificate(t *testing.T) {
	result, err := FetchEncryptionCertificate(HyperProtectOsHpvs, "")
	if err != nil {
		t.Errorf("failed to fetch encryption certificate - %v", err)
	}

	assert.Equal(t, result, cert.EncryptionCertificateHpvs)
}

// Testcase to check if FetchEncryptionCertificate() is able to fetch encryption certificate
func TestFetchEncryptionCertificateRhvs(t *testing.T) {
	_, err := FetchEncryptionCertificate(HyperProtectOsHpcrRhvs, "")
	if err != nil {
		t.Errorf("failed to fetch encryption certificate - %v", err)
	}
}

// Testcase to check if TestGenerateTgzBase64() is able generate base64 of compose tgz
func TestGenerateTgzBase64(t *testing.T) {
	filesFoldersList, err := ListFoldersAndFiles(sampleComposeFolder)
	if err != nil {
		t.Errorf("failed to list files and folders - %v", err)
	}

	result, err := GenerateTgzBase64(filesFoldersList)
	if err != nil {
		t.Errorf("failed to generate TGZ base64 - %v", err)
	}

	assert.NotEmpty(t, result)
}

// Testcase to check if VerifyContractWithSchema() is able to verify schema of contract
func TestVerifyContractWithSchema(t *testing.T) {
	contract, err := ReadDataFromFile(simpleContractPath)
	if err != nil {
		t.Errorf("failed to read contract - %v", err)
	}

	err = VerifyContractWithSchema(contract, "")
	if err != nil {
		t.Errorf("schema verification failed - %v", err)
	}
}

// Testcase to check if VerifyContractWithSchema() is able to throw error for invalid contract
func TestVerifyContractWithSchemaInvalid(t *testing.T) {
	contract, err := ReadDataFromFile(simpleInvalidContractPath)
	if err != nil {
		t.Errorf("failed to read contract - %v", err)
	}

	err = VerifyContractWithSchema(contract, "")

	assert.Error(t, err)
}

// Testcase to check if fetchContractSchema() is able to fetch contract schema
func TestFetchContractSchema(t *testing.T) {
	result, err := fetchContractSchema("")
	if err != nil {
		t.Errorf("failed to fetch contract schema - %v", err)
	}

	assert.NotEmpty(t, result)
}

// Testcase to check if fetchContractSchema() is able to fetch hpcr-rhvs contract schema
func TestFetchContractSchemaRhvs(t *testing.T) {
	result, err := fetchContractSchema(HyperProtectOsHpcrRhvs)
	if err != nil {
		t.Errorf("failed to fetch contract schema - %v", err)
	}

	assert.NotEmpty(t, result)
}

// TestGetOpenSSLPath_WithEnvVarSet tests the case when the OPENSSL_BIN environment variable is set.
// It should return the value of the environment variable instead of the default "openssl".
func TestGetOpenSSLPath_WithEnvVarSet(t *testing.T) {
	expectedPath := "/usr/bin/openssl"

	// Set the environment variable
	os.Setenv("OPENSSL_BIN", expectedPath)
	defer os.Unsetenv("OPENSSL_BIN")

	result := GetOpenSSLPath()
	if result != expectedPath {
		t.Errorf("expected %s, got %s", expectedPath, result)
	}
}

// TestGetOpenSSLPath_WithoutEnvVarSet tests the fallback case when OPENSSL_BIN is not set.
// It should return the default command name "openssl".
func TestGetOpenSSLPath_WithoutEnvVarSet(t *testing.T) {
	// Ensure env variable is not set
	os.Unsetenv("OPENSSL_BIN")

	result := GetOpenSSLPath()
	expected := "openssl"

	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}
