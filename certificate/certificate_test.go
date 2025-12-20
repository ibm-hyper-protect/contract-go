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
	sampleEncryptionCertVersions = []string{"1.0.20", "1.0.21", "1.0.22"}
	sampleCertDownloadTemplate   = "https://hpvsvpcubuntu.s3.us.cloud-object-storage.appdomain.cloud/s390x-{{.Patch}}/ibm-hyper-protect-container-runtime-{{.Major}}-{{.Minor}}-s390x-{{.Patch}}-encrypt.crt"
)

// Testcase to check if GetEncryptionCertificateFromJson() gets encryption certificate as per version constraint
func TestGetEncryptionCertificateFromJson(t *testing.T) {
	version := "> 1.0.0"

	key, value, err := HpcrGetEncryptionCertificateFromJson(sampleJsonData, version)
	if err != nil {
		t.Errorf("failed to get encryption certificate from JSON - %v", err)
	}

	assert.Equal(t, key, "4.0.0")
	assert.Equal(t, value, "data2")
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

// Testcase to check both DownloadEncryptionCertificates() and GetEncryptionCertificateFromJson() together
func TestCombined(t *testing.T) {
	certs, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "", sampleCertDownloadTemplate)
	if err != nil {
		t.Errorf("failed to download HPCR encryption certificates - %v", err)
	}

	version := "> 1.0.20"

	key, _, err := HpcrGetEncryptionCertificateFromJson(certs, version)
	if err != nil {
		t.Errorf("failed to get encryption certificate from JSON - %v", err)
	}

	assert.Equal(t, key, "1.0.22")
}

// Testcase to CheckEncryptionCertValidity() is able to validate encryption certificate
func TestHpcrDownloadEncryptionCertificates(t *testing.T) {
	encryptionCert, err := gen.ReadDataFromFile("../samples/encryption-cert/active.crt")
	if err != nil {
		t.Errorf("failed to get encrypted checksum - %v", err)
	}
	_, err = HpcrValidateEncryptionCertificate(encryptionCert)
	assert.NoError(t, err)
}
