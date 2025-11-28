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

	simpleNetworkConfigPath        = "../../samples/network/network_config.yaml"
	simpleInvalidNetworkConfigPath = "../../samples/network/network_config_invalid.yaml"

	simpleWorkloadPath = "../../samples/workload.yaml"

	certificateDownloadUrl = "https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-15-encrypt.crt"

	sampleStringData   = "sashwatk"
	sampleBase64Data   = "c2FzaHdhdGs="
	sampleDataChecksum = "05fb716cba07a0cdda231f1aa19621ce9e183a4fb6e650b459bc3c5db7593e42"

	sampleCertificateJson = `{
		"1.0.0": {
			"cert": "data1",
			"status": "test1",
			"expiry_date": "26-02-26 12:27:33 GMT",
			"expiry_days": "1"
		},
		"3.5.10": {
			"cert": "data4",
			"status": "test2",
			"expiry_date": "26-02-26 12:27:33 GMT",
			"expiry_days": "2"
		}
	}`

	sampleComposeFolder = "../../samples/tgz"
	// active.crt will be valid up to November 9, 2030
	sampleEncryptionCertificate        = "../../samples/encryption-cert/active.crt"
	sampleEncryptionCertificateExpired = "../../samples/encryption-cert/expired.crt"

	//HPCC gzipped initdata test case
	sampleStringToGzip = "env: hyper-protect-basic.njLuN8QAL9VceUyiYmDzSyAPvVowCTyw4qDJb/Y3z8sR884gPPjHESXnkJAgDnLRl1P24xVzOXe117IQGp+ayQyrHA+40dA+RF64WNs2ZGPHoVmrIfsrEnS8WjrHla00vaN00xCdoA2DehlVYWDISN/HD9vcdPzh7nc6oPoU9/iyWuNWNJUp/QOuJipg5Yu2he5eBf0R7zVdMghKiJQ86sW1blgsUIiWnZsy9Hia+yHLmDE4OsnkgciJJYMvzarMWHOjwwEyhKPNxoVGfxM8f2pp13gx9QY2tWGIVSDFqyWJudAKZ8yvDEVL3x1FlpxG9zcMFDmAbviZhKykMaDmbDeH60+SPneyUV7x/X132d+Nyd2DvCMS/37Z3vmqfpJSxsam5UCT68f1t5Znmk4MNBFcnMI3wFkdTfazUO+2qk1LwgLM2ZFdajtgIhMLua1UOTITiHRbvmAcLppucA7w1ZkqB2gFZCVVKvIcmOHeLYPklZiHTYPnQHlLeS90sk9YoM0BNL42L7JrtTs6EVjSAgVQxDruiERbsjpQy9KwltLOVjYEDQ4v0fpAxxg6GpKds3j9vcOI+9RlABTW10RgrIZsC+QjaB+mra1PFHvcHITkPjbSmtoXXDmD22YiNReK+bYpikvEOgFRi6srrYzOG6oNDygMUQ6+PIwncwkI9V0=.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"
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

// Testcase to check if FetchEncryptionCertificate() fetches encryption certificate for HPVS
func TestFetchEncryptionCertificate(t *testing.T) {
	result, err := FetchEncryptionCertificate(HyperProtectOsHpvs, "")
	if err != nil {
		t.Errorf("failed to fetch encryption certificate - %v", err)
	}

	assert.Equal(t, result, cert.EncryptionCertificateHpvs)
}

// Testcase to check if FetchEncryptionCertificate() is able to fetch encryption certificate for HPCR RHVS
func TestFetchEncryptionCertificateRhvs(t *testing.T) {
	_, err := FetchEncryptionCertificate(HyperProtectOsHpcrRhvs, "")
	if err != nil {
		t.Errorf("failed to fetch encryption certificate - %v", err)
	}
}

// Testcase to check if FetchEncryptionCertificate() is able to fetch encryption certificate for HPCC peerpods
func TestFetchEncryptionCertificateHpcc(t *testing.T) {
	_, err := FetchEncryptionCertificate(HyperProtectConfidentialContainerPeerPods, "")
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

// Testcase to check if VerifyNetworkSchema() is able to verify schema of network-config
func TestVerifyNetworkSchema(t *testing.T) {
	network, err := ReadDataFromFile(simpleNetworkConfigPath)
	if err != nil {
		t.Errorf("failed to read network config file - %v", err)
	}

	err = VerifyNetworkSchema(network)

	assert.NoError(t, err)
}

// Testcase to check if VerifyNetworkSchema() is able to throw error for invalid network-config
func TestVerifyNetworkSchemaInvalid(t *testing.T) {
	network, err := ReadDataFromFile(simpleInvalidNetworkConfigPath)
	if err != nil {
		t.Errorf("failed to read network config file - %v", err)
	}

	err = VerifyNetworkSchema(network)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "additionalProperties 'enc' not allowed")
}

// Testcase to check if yamlParse() is able to unmarshell the YAML file
func TestNetworkConfigYamlParse(t *testing.T) {
	network, err := ReadDataFromFile(simpleInvalidNetworkConfigPath)
	if err != nil {
		t.Errorf("failed to read network config file - %v", err)
	}
	result, err := yamlParse(network)
	if err != nil {
		t.Errorf("failed to unmarshell the YAML file - %v", err)
	}

	assert.NotEmpty(t, result)
}

// Testcase to check encryption certificate validity during certificate download
func TestCheckEncryptionCertValidity(t *testing.T) {
	data, err := os.ReadFile(sampleEncryptionCertificate)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	cert_status, _, _, err := CheckEncryptionCertValidity(string(data)) // sample certificate is valid till 9th nov 2030
	assert.NoError(t, err)
	assert.Contains(t, cert_status, "valid")
}

// Testcase to check encryption certificate validity that is expired during certificate download
func TestCheckExpiredEncryptionCertValidity(t *testing.T) {
	data, err := os.ReadFile(sampleEncryptionCertificateExpired)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	cert_status, _, _, err := CheckEncryptionCertValidity(string(data))
	assert.NoError(t, err)
	assert.Contains(t, cert_status, "expired")
}

// Testcase to check encryption certificate validity during contract encryption
func TestCheckEncryptionCertValidityDuringContractEncryption(t *testing.T) {
	data, err := os.ReadFile(sampleEncryptionCertificate) // sample certificate is valid till 9th nov 2030
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	cert_status, err := CheckEncryptionCertValidityForContractEncryption(string(data))
	assert.NoError(t, err)
	assert.Contains(t, cert_status, "Encryption certificate is valid for another")
}

// Testcase to check encryption certificate validity that is expired during contract encryption
func TestCheckExpiredEncryptionCertValidityDuringContractEncryption(t *testing.T) {
	data, err := os.ReadFile(sampleEncryptionCertificateExpired)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	_, err = CheckEncryptionCertValidityForContractEncryption(string(data))
	assert.Contains(t, err.Error(), "Encryption certificate has already expired")
}

// Testcase to check GzipInitData() is able to gzip data
func TestGzipInitData(t *testing.T) {
	data, err := GzipInitData(sampleStringToGzip)
	if err != nil {
		t.Errorf("failed to create gzipped data - %v", err)
	}
	assert.NotEmpty(t, data)

}
