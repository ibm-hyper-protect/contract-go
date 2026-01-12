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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	defaultEncCertUrlTemplate    = "https://hpvsvpcubuntu.s3.us.cloud-object-storage.appdomain.cloud/s390x-{{.Patch}}/ibm-hyper-protect-container-runtime-{{.Major}}-{{.Minor}}-s390x-{{.Patch}}-encrypt.crt"
	missingParameterErrStatement = "required parameter is missing"
	formatJson                   = "json"
	formatYaml                   = "yaml"
	defaultFormat                = formatJson
)

type CertSpec struct {
	Major string
	Minor string
	Patch string
}

// HpcrGetEncryptionCertificateFromJson extracts a specific version's encryption certificate from downloaded certificates.
// It parses the JSON/YAML output from HpcrDownloadEncryptionCertificates and returns the certificate
// for the requested version.
//
// Parameters:
//   - encryptionCertificateJson: JSON or YAML formatted certificate data from HpcrDownloadEncryptionCertificates
//   - version: Specific HPCR version to extract (e.g., "1.1.15")
//
// Returns:
//   - Version string of the extracted certificate
//   - PEM-formatted encryption certificate
//   - Error if version not found or data is invalid
func HpcrGetEncryptionCertificateFromJson(encryptionCertificateJson, version string) (string, string, error) {
	if gen.CheckIfEmpty(encryptionCertificateJson, version) {
		return "", "", fmt.Errorf(missingParameterErrStatement)
	}

	return gen.GetDataFromLatestVersion(encryptionCertificateJson, version)
}

// HpcrDownloadEncryptionCertificates downloads encryption certificates for specified HPCR versions from IBM Cloud.
// It retrieves certificates for each version in the list, validates their existence and expiry,
// and returns them in either JSON or YAML format.
//
// Parameters:
//   - versionList: List of HPCR versions to download (e.g., []string{"1.1.14", "1.1.15"})
//   - formatType: Output format - "json" or "yaml" (defaults to "json" if empty)
//   - certDownloadUrlTemplate: Custom URL template for certificate download (uses IBM Cloud default if empty)
//
// Returns:
//   - JSON or YAML formatted map of versions to certificates with status and expiry information
//   - Error if download fails or version not found
func HpcrDownloadEncryptionCertificates(versionList []string, formatType, certDownloadUrlTemplate string) (string, error) {
	if certDownloadUrlTemplate == "" {
		certDownloadUrlTemplate = defaultEncCertUrlTemplate
	}

	if formatType == "" {
		formatType = defaultFormat
	}

	if len(versionList) == 0 {
		return "", fmt.Errorf(missingParameterErrStatement)
	}

	var vertCertMapVersion = make(map[string]map[string]string)

	for _, version := range versionList {
		verSpec := strings.Split(version, ".")
		if !strings.Contains(version, ".") || len(verSpec) != 3 {
			return "", fmt.Errorf("invalid version format: '%s'. Expected comma-separated versions, e.g., 1.0.21 or 1.0.21,1.0.22", version)
		}
		urlTemplate := template.New("url")
		urlTemplate, err := urlTemplate.Parse(certDownloadUrlTemplate)
		if err != nil {
			return "", fmt.Errorf("failed to create url template - %v", err)
		}
		builder := &strings.Builder{}
		err = urlTemplate.Execute(builder, CertSpec{verSpec[0], verSpec[1], verSpec[2]})
		if err != nil {
			return "", fmt.Errorf("failed to apply template - %v", err)
		}

		url := builder.String()
		status, err := gen.CheckUrlExists(url)
		if err != nil {
			return "", fmt.Errorf("failed to check if URL exists - %v", err)
		}
		if !status {
			return "", fmt.Errorf("encryption certificate doesn't exist in %s", url)
		}

		cert, err := gen.CertificateDownloader(url)
		if err != nil {
			return "", fmt.Errorf("failed to download encryption certificate - %v", err)
		}

		cert_status, daysLeft, certificateExpiryDate, err := gen.CheckEncryptionCertValidity(cert)
		if err != nil {
			return "", err
		}
		var verCertMap = make(map[string]string)
		verCertMap["cert"] = cert
		verCertMap["status"] = cert_status
		verCertMap["expiry_days"] = strconv.Itoa(daysLeft)
		verCertMap["expiry_date"] = certificateExpiryDate
		vertCertMapVersion[version] = verCertMap
	}

	switch formatType {
	case formatJson:
		jsonBytes, err := json.Marshal(vertCertMapVersion)
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON - %v", err)
		}

		return string(jsonBytes), nil
	case formatYaml:
		yamlBytes, err := yaml.Marshal(vertCertMapVersion)
		if err != nil {
			return "", fmt.Errorf("failed to marshal YAML - %v", err)
		}
		return string(yamlBytes), nil
	default:
		return "", fmt.Errorf("invalid output format")
	}
}

// HpcrValidateEncryptionCertificate validates an encryption certificate and returns expiry information.
// It checks the certificate's validity period and returns a message indicating whether the certificate
// is valid, about to expire, or has already expired.
//
// Parameters:
//   - encryptionCert: PEM-formatted encryption certificate to validate
//
// Returns:
//   - Validation message with expiry information (days remaining or expiration date)
//   - Error if certificate is invalid, corrupted, or has expired
func HpcrValidateEncryptionCertificate(encryptionCert string) (string, error) {
	msg, err := gen.CheckEncryptionCertValidityForContractEncryption(encryptionCert)
	if err != nil {
		return "", err
	}
	return msg, nil
}
