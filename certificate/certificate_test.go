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

package certificate

import (
	"testing"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
	"github.com/stretchr/testify/assert"
)

var (
	sampleJsonData = `{
		"1.0.0": {
			"cert": "data1",
			"status": "test1",
			"expiry_date": "26-02-26 12:27:33 GMT",
			"expiry_days": "1"
		},
		"4.0.0": {
			"cert": "data2",
			"status": "test2",
			"expiry_date": "26-02-26 12:27:33 GMT",
			"expiry_days": "2"
		}
	}`
	sampleEncryptionCertVersions       = []string{"1.0.20", "1.0.21", "1.0.22"}
	sampleInvalidEncryptionCertVersion = []string{"abc", "xy.z"}
	sampleCertDownloadTemplate         = "https://hpvsvpcubuntu.s3.us.cloud-object-storage.appdomain.cloud/s390x-{{.Patch}}/ibm-hyper-protect-container-runtime-{{.Major}}-{{.Minor}}-s390x-{{.Patch}}-encrypt.crt"

	sampleEncryptionCertPath = "../samples/encryption-cert/active.crt"
)

// Testcase to check if GetEncryptionCertificateFromJson() gets encryption certificate as per version constraint
func TestGetEncryptionCertificateFromJson(t *testing.T) {
	version := "> 1.0.0"

	key, cert, expiry_date, expiry_days, status, err := HpcrGetEncryptionCertificateFromJson(sampleJsonData, version)
	if err != nil {
		t.Errorf("failed to get encryption certificate from JSON - %v", err)
	}

	assert.Equal(t, key, "4.0.0")
	assert.Equal(t, cert, "data2")
	assert.Equal(t, expiry_date, "26-02-26 12:27:33 GMT")
	assert.Equal(t, expiry_days, "2")
	assert.Equal(t, status, "test2")
}

// Testcase to check if DownloadEncryptionCertificates() is able to download encryption certificates as per constraint
func TestDownloadEncryptionCertificates(t *testing.T) {
	certs, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "", "")
	if err != nil {
		t.Errorf("failed to download HPCR encryption certificates - %v", err)
	}

	assert.Contains(t, certs, "1.0.22")
}

// Testcase to check if DownloadEncryptionCertificates() is throwing error if no version is provided
func TestDownloadEncryptionCertificatesWithoutVersion(t *testing.T) {
	_, err := HpcrDownloadEncryptionCertificates([]string{}, "yaml", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required parameter is missing")
}

// Testcase to check if DownloadEncryptionCertificates() is able to download encryption certificates in YAML
func TestDownloadEncryptionCertificatesYaml(t *testing.T) {
	_, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "yaml", "")
	if err != nil {
		t.Errorf("failed to download HPCR encryption certificates - %v", err)
	}
}

// Testcase to check if DownloadEncryptionCertificates() is throwing error if version format is not correct
func TestDownloadEncryptionCertificatesWithInvalidVersionFormat(t *testing.T) {
	_, err := HpcrDownloadEncryptionCertificates(sampleInvalidEncryptionCertVersion, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid version format: 'abc'. Expected comma-separated versions, e.g., 1.0.21 or 1.0.21,1.0.22")
}

// Testcase to check both DownloadEncryptionCertificates() and GetEncryptionCertificateFromJson() together
func TestCombined(t *testing.T) {
	certs, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "", sampleCertDownloadTemplate)
	if err != nil {
		t.Errorf("failed to download HPCR encryption certificates - %v", err)
	}

	version := "> 1.0.20"

	key, _, _, _, _, err := HpcrGetEncryptionCertificateFromJson(certs, version)
	if err != nil {
		t.Errorf("failed to get encryption certificate from JSON - %v", err)
	}

	assert.Equal(t, key, "1.0.22")
}

// Testcase to CheckEncryptionCertValidity() is able to validate encryption certificate
func TestHpcrDownloadEncryptionCertificates(t *testing.T) {
	encryptionCert, err := gen.ReadDataFromFile(sampleEncryptionCertPath)
	if err != nil {
		t.Errorf("failed to get encrypted checksum - %v", err)
	}
	_, err = HpcrValidateEncryptionCertificate(encryptionCert)
	assert.NoError(t, err)
}

// Testcase to check if HpcrGetEncryptionCertificateFromJson() handles empty parameters
func TestHpcrGetEncryptionCertificateFromJsonEmptyJson(t *testing.T) {
	_, _, _, _, _, err := HpcrGetEncryptionCertificateFromJson("", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), missingParameterErrStatement)
}

// Testcase to check if HpcrDownloadEncryptionCertificates() handles YAML format
func TestHpcrDownloadEncryptionCertificatesYamlFormat(t *testing.T) {
	result, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "yaml", sampleCertDownloadTemplate)
	if err != nil {
		t.Errorf("failed to download certificates in YAML format - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Contains(t, result, "1.0.20")
}

// Testcase to check if HpcrVerifyEncryptionCertificateDocument handles empty parameters
func TestHpcrVerifyEncryptionCertificateDocument_EmptyParameters(t *testing.T) {
	valid, msg, err := HpcrVerifyEncryptionCertificateDocument("", "", "", "")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Empty(t, msg)
	assert.Contains(t, err.Error(), missingParameterErrStatement)
}

// Testcase to check if HpcrVerifyAttestationCertificateDocument handles empty parameters
func TestHpcrVerifyAttestationCertificateDocument_EmptyParameters(t *testing.T) {
	valid, msg, err := HpcrVerifyAttestationCertificateDocument("", "", "", "")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Empty(t, msg)
	assert.Contains(t, err.Error(), missingParameterErrStatement)
}

// Testcase to check if HpcrValidateCertificateRevocationList handles empty parameters
func TestHpcrValidateCertificateRevocationList_EmptyParameters(t *testing.T) {
	valid, msg, err := HpcrValidateCertificateRevocationList("", "")
	assert.Error(t, err)
	assert.False(t, valid)
	assert.Empty(t, msg)
	assert.Contains(t, err.Error(), missingParameterErrStatement)
}

// Testcase to check if HpcrListAvailableEncCertVersions returns all available certificates when osType is empty (JSON)
func TestHpcrListAvailableEncCertVersions_AllOsTypes(t *testing.T) {
	result, err := HpcrListAvailableEncCertVersions("", "json")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "ccrt")
	assert.Contains(t, result, "ccrv")
	assert.Contains(t, result, "ccco")
}

// Testcase to check if HpcrListAvailableEncCertVersions returns versions for ccrt (JSON)
func TestHpcrListAvailableEncCertVersions_Ccrt(t *testing.T) {
	result, err := HpcrListAvailableEncCertVersions("ccrt", "json")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "ccrt")
	assert.NotContains(t, result, "ccrv")
	assert.NotContains(t, result, "ccco")
}

// Testcase to check if HpcrListAvailableEncCertVersions returns versions for ccrv (JSON)
func TestHpcrListAvailableEncCertVersions_Ccrv(t *testing.T) {
	result, err := HpcrListAvailableEncCertVersions("ccrv", "json")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "ccrv")
	assert.NotContains(t, result, "ccrt")
	assert.NotContains(t, result, "ccco")
}

// Testcase to check if HpcrListAvailableEncCertVersions returns versions for ccco (JSON)
func TestHpcrListAvailableEncCertVersions_Ccco(t *testing.T) {
	result, err := HpcrListAvailableEncCertVersions("ccco", "json")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "ccco")
	assert.NotContains(t, result, "ccrt")
	assert.NotContains(t, result, "ccrv")
}

// Testcase to check if HpcrListAvailableEncCertVersions handles invalid OS type
func TestHpcrListAvailableEncCertVersions_InvalidOsType(t *testing.T) {
	result, err := HpcrListAvailableEncCertVersions("invalid-os", "json")
	assert.Error(t, err)
	assert.Empty(t, result)
	assert.Contains(t, err.Error(), "invalid OS type")
}

// Testcase to check if HpcrListAvailableEncCertVersions is case-insensitive
func TestHpcrListAvailableEncCertVersions_CaseInsensitive(t *testing.T) {
	upperResult, err1 := HpcrListAvailableEncCertVersions("CCRT", "json")
	assert.NoError(t, err1)
	lowerResult, err2 := HpcrListAvailableEncCertVersions("ccrt", "json")
	assert.NoError(t, err2)
	mixedResult, err3 := HpcrListAvailableEncCertVersions("CcRt", "json")
	assert.NoError(t, err3)
	assert.Equal(t, lowerResult, upperResult)
	assert.Equal(t, lowerResult, mixedResult)
}

// Testcase to check if HpcrListAvailableEncCertVersions supports "hpvs" as alias for "ccrt"
func TestHpcrListAvailableEncCertVersions_HpvsAlias(t *testing.T) {
	hpvsResult, err1 := HpcrListAvailableEncCertVersions("hpvs", "json")
	assert.NoError(t, err1)
	ccrtResult, err2 := HpcrListAvailableEncCertVersions("ccrt", "json")
	assert.NoError(t, err2)
	// Both should return the same result (ccrt certificates)
	assert.Equal(t, ccrtResult, hpvsResult)
	assert.Contains(t, hpvsResult, "ccrt")
	assert.NotContains(t, hpvsResult, "hpvs")
}

// Testcase to check if HpcrListAvailableEncCertVersions returns YAML format
func TestHpcrListAvailableEncCertVersions_YamlFormat(t *testing.T) {
	result, err := HpcrListAvailableEncCertVersions("ccrt", "yaml")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Contains(t, result, "ccrt:")
	assert.Contains(t, result, "- ")
}

// Testcase to check if HpcrListAvailableEncCertVersions defaults to JSON when format is empty
func TestHpcrListAvailableEncCertVersions_DefaultFormat(t *testing.T) {
	result, err := HpcrListAvailableEncCertVersions("ccrt", "")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	// JSON format should have quotes and brackets
	assert.Contains(t, result, "{")
	assert.Contains(t, result, "\"ccrt\"")
}

// Testcase to check if HpcrListAvailableEncCertVersions handles invalid format
func TestHpcrListAvailableEncCertVersions_InvalidFormat(t *testing.T) {
	result, err := HpcrListAvailableEncCertVersions("ccrt", "xml")
	assert.Error(t, err)
	assert.Empty(t, result)
	assert.Contains(t, err.Error(), "invalid output format")
}
