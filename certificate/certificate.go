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

	crt "github.com/ibm-hyper-protect/contract-go/v2/common/cert"
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

// HpcrGetEncryptionCertificateFromJson extracts a specific version's encryption certificate
// from the output of [HpcrDownloadEncryptionCertificates].
//
// Use this function after downloading certificates with [HpcrDownloadEncryptionCertificates]
// to extract the certificate, version, expiry details, and status for a specific IBM Confidential
// Computing Container Runtime version.
//
// Parameters:
//   - encryptionCertificateJson: JSON or YAML formatted certificate data (output from [HpcrDownloadEncryptionCertificates])
//   - version: Specific version to extract (e.g., "1.1.15")
//
// Returns:
//   - Version string of the extracted certificate
//   - PEM-formatted encryption certificate for use with contract encryption functions
//   - Expiry date of the encryption certificate (human-readable date string)
//   - Expiry days remaining as a string (e.g., "365")
//   - Status of the certificate (e.g., "valid", "expired")
//   - Error if version not found or data is invalid
func HpcrGetEncryptionCertificateFromJson(encryptionCertificateJson, version string) (string, string, string, string, string, error) {
	if gen.CheckIfEmpty(encryptionCertificateJson, version) {
		return "", "", "", "", "", fmt.Errorf(missingParameterErrStatement)
	}

	latestVersion, certInfo, err := gen.GetDataFromLatestVersion(encryptionCertificateJson, version)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to get latest version - %v", err)
	}
	return latestVersion, certInfo["cert"], certInfo["expiry_date"], certInfo["expiry_days"], certInfo["status"], nil
}

// HpcrDownloadEncryptionCertificates downloads encryption certificates for specified IBM
// Confidential Computing Container Runtime versions from IBM Cloud.
//
// Use this function to download the IBM encryption certificates required for encrypting
// contract sections. Each version of the runtime may have a different encryption certificate.
// The certificates are used to encrypt the random AES password in the "hyper-protect-basic"
// encryption format. You can then extract individual certificates using [HpcrGetEncryptionCertificateFromJson].
//
// Parameters:
//   - versionList: List of runtime versions to download certificates for (e.g., []string{"1.1.14", "1.1.15"}).
//     Version format must be "major.minor.patch" (e.g., "1.1.15").
//   - formatType: Output format — "json" or "yaml" (defaults to "json" if empty)
//   - certDownloadUrlTemplate: Custom URL template for certificate download. If empty, uses the
//     default IBM Cloud Object Storage URL. Template variables: {{.Major}}, {{.Minor}}, {{.Patch}}
//
// Returns:
//   - JSON or YAML formatted map of versions to certificates, each with cert, status, expiry_days,
//     and expiry_date fields
//   - Error if download fails, version format is invalid, or certificate not found
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

// HpcrValidateEncryptionCertificate validates an IBM encryption certificate and returns its expiry status.
//
// Use this function to check whether an encryption certificate is still valid before using it
// for contract encryption. This is especially important in CI/CD pipelines and automation
// to detect expiring certificates early and avoid deployment failures.
//
// Parameters:
//   - encryptionCert: PEM-formatted IBM encryption certificate to validate
//
// Returns:
//   - Validation message indicating the certificate status (valid with days remaining, or expired)
//   - Error if the certificate is invalid, corrupted, or has expired
func HpcrValidateEncryptionCertificate(encryptionCert string) (string, error) {
	msg, err := gen.CheckEncryptionCertValidityForContractEncryption(encryptionCert)
	if err != nil {
		return "", err
	}
	return msg, nil
}

// HpcrVerifyEncryptionCertificateDocument verifies an encryption certificate
// document by checking issuer chain, document signature, and validity dates.
//
// Parameters:
//   - encryptionCert: encryption certificate document content
//   - ibmIntermediateCert: IBM intermediate certificate content
//   - digicertIntermediateCert: DigiCert intermediate certificate content
//   - digicertRootCert: DigiCert root certificate content
//
// Returns:
//   - valid: true if the certificate document is valid
//   - message: Detailed validation message
//   - error: Error with stage information if validation fails
func HpcrVerifyEncryptionCertificateDocument(encryptionCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert string) (bool, string, error) {
	if gen.CheckIfEmpty(encryptionCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert) {
		return false, "", fmt.Errorf(missingParameterErrStatement)
	}

	valid, msg, err := crt.ValidateEncryptionCertificateDocument(encryptionCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert)
	if err != nil {
		return false, "", err
	}

	return valid, msg, nil
}

// HpcrVerifyAttestationCertificateDocument verifies an attestation certificate
// document by checking issuer chain, document signature, and validity dates.
//
// Parameters:
//   - attestationCert: attestation certificate document content
//   - ibmIntermediateCert: IBM intermediate certificate content
//   - digicertIntermediateCert: DigiCert intermediate certificate content
//   - digicertRootCert: DigiCert root certificate content
//
// Returns:
//   - valid: true if the certificate document is valid
//   - message: Detailed validation message
//   - error: Error with stage information if validation fails
func HpcrVerifyAttestationCertificateDocument(attestationCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert string) (bool, string, error) {
	if gen.CheckIfEmpty(attestationCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert) {
		return false, "", fmt.Errorf(missingParameterErrStatement)
	}

	valid, msg, err := crt.ValidateAttestationCertificateDocument(attestationCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert)
	if err != nil {
		return false, "", err
	}

	return valid, msg, nil
}

// HpcrValidateCertificateRevocationList validates CRL metadata/signature and checks
// that a certificate document (encryption or attestation) is not revoked.
//
// Parameters:
//   - certificateDocument: certificate document content (encryption or attestation)
//   - ibmIntermediateCert: IBM intermediate certificate content
//
// Returns:
//   - valid: true if CRL validation succeeded and certificate is not revoked
//   - message: Detailed validation message
//   - error: Error with stage information if validation fails
func HpcrValidateCertificateRevocationList(certificateDocument, ibmIntermediateCert string) (bool, string, error) {
	if gen.CheckIfEmpty(certificateDocument, ibmIntermediateCert) {
		return false, "", fmt.Errorf(missingParameterErrStatement)
	}

	valid, msg, err := crt.ValidateCertificateRevocationList(certificateDocument, ibmIntermediateCert)
	if err != nil {
		return false, "", err
	}

	return valid, msg, nil
}
