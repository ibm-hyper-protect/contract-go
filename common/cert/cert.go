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

package cert

import (
	"fmt"
	"strings"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

// ValidateCertificateChain validates a complete certificate chain using OpenSSL verify command.
// It verifies the trust chain from encryption certificate through intermediate to root CA.
//
// Parameters:
//   - encCertPEM: PEM-formatted encryption certificate (leaf certificate)
//   - intermediateCertPEM: PEM-formatted intermediate CA certificate
//   - rootCertPEM: PEM-formatted root CA certificate
//
// Returns:
//   - valid: true if certificate chain is valid, false otherwise
//   - message: Detailed validation message including expiry information
//   - error: Error if validation process fails
func ValidateCertificateChain(encCertPEM, intermediateCertPEM, rootCertPEM string) (bool, string, error) {
	if gen.CheckIfEmpty(encCertPEM, intermediateCertPEM, rootCertPEM) {
		return false, "", fmt.Errorf("required parameter is missing")
	}

	encCertPath, err := gen.CreateTempFile(encCertPEM)
	if err != nil {
		return false, "", fmt.Errorf("failed to create temp file for encryption certificate - %v", err)
	}
	defer gen.RemoveTempFile(encCertPath)

	intermediateCertPath, err := gen.CreateTempFile(intermediateCertPEM)
	if err != nil {
		return false, "", fmt.Errorf("failed to create temp file for intermediate certificate - %v", err)
	}
	defer gen.RemoveTempFile(intermediateCertPath)

	rootCertPath, err := gen.CreateTempFile(rootCertPEM)
	if err != nil {
		return false, "", fmt.Errorf("failed to create temp file for root certificate - %v", err)
	}
	defer gen.RemoveTempFile(rootCertPath)

	result, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "verify", "-CAfile", rootCertPath, "-untrusted", intermediateCertPath, encCertPath)

	if err != nil {
		errMsg := strings.TrimSpace(result)
		if errMsg == "" {
			errMsg = err.Error()
		}
		return false, errMsg, fmt.Errorf("certificate chain validation failed - %v", errMsg)
	}

	if strings.Contains(result, "OK") {
		// Get certificate expiry information
		expiryMsg, err := getCertificateExpiry(encCertPath)
		if err != nil {
			return true, "Certificate chain is valid", nil
		}
		return true, fmt.Sprintf("Certificate chain is valid. %s", expiryMsg), nil
	}

	return false, strings.TrimSpace(result), fmt.Errorf("certificate chain validation failed")
}

// getCertificateExpiry gets the expiry information from a certificate using OpenSSL.
// It extracts the notAfter date from the certificate and formats it as a readable message.
//
// Parameters:
//   - certPath: File path to the certificate
//
// Returns:
//   - Formatted expiry message (e.g., "Certificate expires on Jan 15 23:59:59 2027 GMT")
//   - Error if extraction fails
func getCertificateExpiry(certPath string) (string, error) {
	// Get the end date of the certificate
	result, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "x509", "-in", certPath, "-noout", "-enddate")

	if err != nil {
		return "", err
	}

	result = strings.TrimSpace(result)
	if strings.HasPrefix(result, "notAfter=") {
		dateStr := strings.TrimPrefix(result, "notAfter=")
		return fmt.Sprintf("Certificate expires on %s", dateStr), nil
	}

	return "", fmt.Errorf("failed to parse certificate expiry")
}

// CheckCertificateRevocation checks if a certificate has been revoked using a CRL.
// It uses OpenSSL verify command with the -CRLfile option to check revocation status.
//
// Parameters:
//   - certPEM: PEM-formatted certificate to check
//   - crlPEM: PEM-formatted Certificate Revocation List
//
// Returns:
//   - revoked: true if certificate is revoked, false otherwise
//   - message: Detailed revocation status message
//   - error: Error if check fails
func CheckCertificateRevocation(certPEM, crlPEM string) (bool, string, error) {
	if gen.CheckIfEmpty(certPEM, crlPEM) {
		return false, "", fmt.Errorf("required parameter is missing")
	}

	// Create temporary files
	certPath, err := gen.CreateTempFile(certPEM)
	if err != nil {
		return false, "", fmt.Errorf("failed to create temp file for certificate - %v", err)
	}
	defer gen.RemoveTempFile(certPath)

	crlPath, err := gen.CreateTempFile(crlPEM)
	if err != nil {
		return false, "", fmt.Errorf("failed to create temp file for CRL - %v", err)
	}
	defer gen.RemoveTempFile(crlPath)

	result, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "verify", "-crl_check", "-CRLfile", crlPath, certPath)

	if err != nil {
		// Check if error indicates revocation
		errMsg := strings.TrimSpace(result)
		if strings.Contains(errMsg, "revoked") || strings.Contains(strings.ToLower(errMsg), "revoked") {
			return true, fmt.Sprintf("Certificate is revoked: %s", errMsg), nil
		}
		return false, "", fmt.Errorf("CRL check failed - %v", errMsg)
	}

	// Certificate is not revoked
	if strings.Contains(result, "OK") {
		return false, "Certificate is not revoked", nil
	}

	return false, strings.TrimSpace(result), nil
}

// DownloadCRL downloads a Certificate Revocation List from the specified URL.
// It uses the existing certificate downloader from common/general.
//
// Parameters:
//   - crlURL: URL of the CRL to download
//
// Returns:
//   - PEM-formatted CRL data
//   - Error if download fails
func DownloadCRL(crlURL string) (string, error) {
	if gen.CheckIfEmpty(crlURL) {
		return "", fmt.Errorf("required parameter is missing")
	}

	crlData, err := gen.CertificateDownloader(crlURL)
	if err != nil {
		return "", fmt.Errorf("failed to download CRL - %v", err)
	}

	return crlData, nil
}
