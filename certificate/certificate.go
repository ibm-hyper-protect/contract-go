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

// HpcrValidateCertChain validates the complete certificate chain
// including signatures, expiry, and trust relationships. Users must provide all
// certificates (encryption, intermediate, and root).
//
// This function performs comprehensive validation by:
//   - Verifying that the encryption certificate is signed by the intermediate certificate
//   - Verifying that the intermediate certificate is signed by the root certificate
//   - Checking that all certificates are within their validity periods
//   - Verifying the trust chain (issuer/subject matching)
//   - Providing warnings for certificates expiring soon
//
// The validation is performed using OpenSSL verify command, which provides
// industry-standard certificate chain validation.
//
// Parameters:
//   - encryptionCert: PEM-formatted encryption certificate
//   - intermediateCert: PEM-formatted intermediate certificate
//   - rootCert: PEM-formatted root certificate (e.g., DigiCert Trusted Root G4)
//
// Returns:
//   - valid: true if certificate chain is valid, false otherwise
//   - message: Detailed validation message with expiry information and warnings
//   - error: Error if validation fails or parameters are invalid
func HpcrValidateCertChain(encryptionCert, intermediateCert, rootCert string) (bool, string, error) {
	if gen.CheckIfEmpty(encryptionCert, intermediateCert, rootCert) {
		return false, "", fmt.Errorf(missingParameterErrStatement)
	}

	valid, msg, err := crt.ValidateCertificateChain(encryptionCert, intermediateCert, rootCert)
	if err != nil {
		return false, msg, err
	}

	return valid, msg, nil
}

// HpcrCheckCertificateRevocation checks if a certificate has been revoked
// by checking against the provided Certificate Revocation List (CRL).
// Users must provide both the certificate and the CRL.
//
// This function verifies that:
//   - The certificate is not in the CRL's revoked certificates list
//   - The CRL is still valid (not expired)
//   - Returns detailed revocation information if the certificate is revoked
//
// The validation is performed using OpenSSL verify command with CRL checking,
// which provides industry-standard revocation verification.
//
// Parameters:
//   - encryptionCert: PEM-formatted certificate to check
//   - crlData: PEM-formatted Certificate Revocation List
//
// Returns:
//   - revoked: true if certificate is revoked, false otherwise
//   - message: Detailed revocation status message
//   - error: Error if check fails or parameters are invalid
func HpcrCheckCertificateRevocation(encryptionCert, crlData string) (bool, string, error) {
	if gen.CheckIfEmpty(encryptionCert, crlData) {
		return false, "", fmt.Errorf(missingParameterErrStatement)
	}

	// Check revocation status using OpenSSL
	revoked, msg, err := crt.CheckCertificateRevocation(encryptionCert, crlData)
	if err != nil {
		return false, "", err
	}

	return revoked, msg, nil
}

// HpcrDownloadCRL downloads a Certificate Revocation List from the specified URL.
// This is a helper function for users who need to obtain CRLs for revocation checking.
//
// The CRL URL can typically be found in the certificate's CRL Distribution Points
// extension. Common CRL URLs for IBM certificates include DigiCert CRL endpoints.
//
// Parameters:
//   - crlURL: URL of the CRL to download (e.g., "http://crl3.digicert.com/...")
//
// Returns:
//   - PEM-formatted CRL data
//   - Error if download fails or URL is invalid
func HpcrDownloadCRL(crlURL string) (string, error) {
	if gen.CheckIfEmpty(crlURL) {
		return "", fmt.Errorf(missingParameterErrStatement)
	}

	crlData, err := crt.DownloadCRL(crlURL)
	if err != nil {
		return "", err
	}

	return crlData, nil
}
