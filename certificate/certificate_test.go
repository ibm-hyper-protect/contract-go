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

	"github.com/stretchr/testify/assert"
)

var (
	sampleJsonData = `{
		"1.0.0": "data1",
		"1.2.5": "data2",
		"2.0.5": "data3",
		"3.5.10": "data4",
		"4.0.0": "data5"
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
	assert.Equal(t, value, "data5")
}

// Testcase to check if DownloadEncryptionCertificates() is able to download encryption certificates as per constraint
func TestDownloadEncryptionCertificates(t *testing.T) {
	certs, err := HpcrDownloadEncryptionCertificates(sampleEncryptionCertVersions, "", "")
	if err != nil {
		t.Errorf("failed to download HPCR encryption certificates - %v", err)
	}

	assert.Contains(t, certs, "1.0.22")
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
