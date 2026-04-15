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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

const (
	opensslCommandTimeout = 30 * time.Second

	stageCAVerify           = "CA verify"
	stageSigningCertVerify  = "signing cert verify"
	stageDocSignatureVerify = "doc signature verify"
	stageDateVerify         = "date verify"
	stageCRLSignatureVerify = "CRL signature verify"
	stageSerialRevoked      = "serial revoked"
)

var (
	asn1OffsetPattern = regexp.MustCompile(`^\s*([0-9]+):`)
	crlURIRegex       = regexp.MustCompile(`URI:([^\s]+)`)
	serialRegex       = regexp.MustCompile(`Serial Number:\s*([0-9A-Fa-f:]+)`)
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

// ValidateEncryptionCertificateDocument validates an encryption certificate document
// by verifying chain, signature, and certificate validity window.
func ValidateEncryptionCertificateDocument(encryptionCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert string) (bool, string, error) {
	return validateCertificateDocument(
		encryptionCert,
		ibmIntermediateCert,
		digicertIntermediateCert,
		digicertRootCert,
		"encryption",
	)
}

// ValidateAttestationCertificateDocument validates an attestation certificate document
// by verifying chain, signature, and certificate validity window.
func ValidateAttestationCertificateDocument(attestationCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert string) (bool, string, error) {
	return validateCertificateDocument(
		attestationCert,
		ibmIntermediateCert,
		digicertIntermediateCert,
		digicertRootCert,
		"attestation",
	)
}

// validateCertificateDocument runs the shared validation flow for encryption or attestation documents.
func validateCertificateDocument(targetCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert, certType string) (bool, string, error) {
	if gen.CheckIfEmpty(targetCert, ibmIntermediateCert, digicertIntermediateCert, digicertRootCert) {
		return false, "", fmt.Errorf("required parameter is missing")
	}

	targetCertPath, err := gen.CreateTempFile(targetCert)
	if err != nil {
		return false, "", stageError(stageDocSignatureVerify, fmt.Sprintf("failed to create temp file for %s certificate - %v", certType, err))
	}
	defer gen.RemoveTempFile(targetCertPath)

	ibmIntermediatePath, err := gen.CreateTempFile(ibmIntermediateCert)
	if err != nil {
		return false, "", stageError(stageSigningCertVerify, fmt.Sprintf("failed to create temp file for IBM intermediate certificate - %v", err))
	}
	defer gen.RemoveTempFile(ibmIntermediatePath)

	digicertIntermediatePath, err := gen.CreateTempFile(digicertIntermediateCert)
	if err != nil {
		return false, "", stageError(stageCAVerify, fmt.Sprintf("failed to create temp file for DigiCert intermediate certificate - %v", err))
	}
	defer gen.RemoveTempFile(digicertIntermediatePath)

	digicertRootPath, err := gen.CreateTempFile(digicertRootCert)
	if err != nil {
		return false, "", stageError(stageCAVerify, fmt.Sprintf("failed to create temp file for DigiCert root certificate - %v", err))
	}
	defer gen.RemoveTempFile(digicertRootPath)

	// Step 1: Verify DigiCert intermediate certificate.
	if err := verifyCertificateWithCRLFallback(digicertIntermediatePath, digicertRootPath, "", stageCAVerify); err != nil {
		return false, "", err
	}

	// Step 2: Verify IBM intermediate certificate.
	if err := verifyCertificateWithCRLFallback(ibmIntermediatePath, digicertRootPath, digicertIntermediatePath, stageSigningCertVerify); err != nil {
		return false, "", err
	}

	// Step 3: Verify certificate document signature using IBM intermediate public key.
	if err := verifyDocumentSignature(targetCertPath, ibmIntermediatePath); err != nil {
		return false, "", stageError(stageDocSignatureVerify, err.Error())
	}

	// Step 4: Verify validity dates.
	if err := validateCertificateDateWindow(targetCertPath); err != nil {
		return false, "", stageError(stageDateVerify, err.Error())
	}

	return true, fmt.Sprintf("%s certificate document is valid", certType), nil
}

// ValidateCertificateRevocationList validates CRL metadata/signature and checks
// revocation status for both encryption and attestation certificates.
func ValidateCertificateRevocationList(encryptionCert, attestationCert, ibmIntermediateCert string) (bool, string, error) {
	if gen.CheckIfEmpty(encryptionCert, attestationCert, ibmIntermediateCert) {
		return false, "", fmt.Errorf("required parameter is missing")
	}

	encryptionCertPath, err := gen.CreateTempFile(encryptionCert)
	if err != nil {
		return false, "", stageError(stageCRLSignatureVerify, fmt.Sprintf("failed to create temp file for encryption certificate - %v", err))
	}
	defer gen.RemoveTempFile(encryptionCertPath)

	attestationCertPath, err := gen.CreateTempFile(attestationCert)
	if err != nil {
		return false, "", stageError(stageCRLSignatureVerify, fmt.Sprintf("failed to create temp file for attestation certificate - %v", err))
	}
	defer gen.RemoveTempFile(attestationCertPath)

	ibmIntermediatePath, err := gen.CreateTempFile(ibmIntermediateCert)
	if err != nil {
		return false, "", stageError(stageCRLSignatureVerify, fmt.Sprintf("failed to create temp file for IBM intermediate certificate - %v", err))
	}
	defer gen.RemoveTempFile(ibmIntermediatePath)

	crlURL, err := extractCRLDistributionPointFromCertificate(encryptionCertPath)
	if err != nil {
		crlURL, err = extractCRLDistributionPointFromCertificate(attestationCertPath)
		if err != nil {
			return false, "", stageError(stageCRLSignatureVerify, fmt.Sprintf("failed to extract CRL URL - %v", err))
		}
	}

	crlPath, err := downloadCRLFromURLToTempFile(crlURL)
	if err != nil {
		return false, "", stageError(stageCRLSignatureVerify, fmt.Sprintf("failed to download CRL - %v", err))
	}
	defer gen.RemoveTempFile(crlPath)

	crlText, err := validateCRLMetadata(crlPath)
	if err != nil {
		return false, "", stageError(stageCRLSignatureVerify, err.Error())
	}

	if err := verifyCRLSignature(crlPath, ibmIntermediatePath); err != nil {
		return false, "", stageError(stageCRLSignatureVerify, err.Error())
	}

	encryptionSerial, err := extractCertificateSerial(encryptionCertPath)
	if err != nil {
		return false, "", stageError(stageSerialRevoked, fmt.Sprintf("failed to extract encryption certificate serial - %v", err))
	}
	if isCertificateRevoked(crlText, encryptionSerial) {
		return false, "", stageError(stageSerialRevoked, "encryption certificate is listed in CRL")
	}

	attestationSerial, err := extractCertificateSerial(attestationCertPath)
	if err != nil {
		return false, "", stageError(stageSerialRevoked, fmt.Sprintf("failed to extract attestation certificate serial - %v", err))
	}
	if isCertificateRevoked(crlText, attestationSerial) {
		return false, "", stageError(stageSerialRevoked, "attestation certificate is listed in CRL")
	}

	return true, "CRL is valid and both certificates are not revoked", nil
}

// verifyCertificateWithCRLFallback verifies a certificate and falls back to manual CRL download/check when needed.
func verifyCertificateWithCRLFallback(certPath, rootCertPath, untrustedCertPath, stage string) error {
	args := []string{"verify", "-crl_download", "-crl_check", "-CAfile", rootCertPath}
	if untrustedCertPath != "" {
		args = append(args, "-untrusted", untrustedCertPath)
	}
	args = append(args, certPath)

	verifyOutput, verifyErr := runOpenSSLCommand(args...)
	if verifyErr == nil && strings.Contains(verifyOutput, "OK") {
		return nil
	}

	crlURL, err := extractCRLDistributionPointFromCertificate(certPath)
	if err != nil {
		if verifyErr != nil {
			return stageError(stage, fmt.Sprintf("%s (manual fallback setup failed: %v)", verifyOutput, err))
		}
		return stageError(stage, fmt.Sprintf("manual fallback setup failed: %v", err))
	}

	crlPath, err := downloadCRLFromURLToTempFile(crlURL)
	if err != nil {
		return stageError(stage, fmt.Sprintf("failed to download CRL for manual fallback - %v", err))
	}
	defer gen.RemoveTempFile(crlPath)

	fallbackArgs := []string{"verify", "-CAfile", rootCertPath}
	if untrustedCertPath != "" {
		fallbackArgs = append(fallbackArgs, "-untrusted", untrustedCertPath)
	}
	fallbackArgs = append(fallbackArgs, "-CRLfile", crlPath, "-crl_check", certPath)

	fallbackOutput, fallbackErr := runOpenSSLCommand(fallbackArgs...)
	if fallbackErr != nil {
		return stageError(stage, fallbackOutput)
	}
	if !strings.Contains(fallbackOutput, "OK") {
		return stageError(stage, fallbackOutput)
	}

	return nil
}

// verifyDocumentSignature verifies the certificate document signature using IBM intermediate public key and ASN.1 offsets.
func verifyDocumentSignature(documentPath, ibmIntermediatePath string) error {
	pubKeyPath, err := createEmptyTempFilePath()
	if err != nil {
		return fmt.Errorf("failed to create temp file for public key - %v", err)
	}
	defer gen.RemoveTempFile(pubKeyPath)

	if _, err := runOpenSSLCommand("x509", "-in", ibmIntermediatePath, "-pubkey", "-noout", "-out", pubKeyPath); err != nil {
		return fmt.Errorf("failed to extract public key from IBM intermediate certificate - %v", err)
	}

	asn1Output, err := runOpenSSLCommand("asn1parse", "-in", documentPath)
	if err != nil {
		return fmt.Errorf("failed to parse ASN.1 certificate document - %v", err)
	}

	signatureOffset, err := getLastASN1Offset(asn1Output)
	if err != nil {
		return fmt.Errorf("failed to extract signature offset - %v", err)
	}

	signaturePath, err := createEmptyTempFilePath()
	if err != nil {
		return fmt.Errorf("failed to create temp file for signature - %v", err)
	}
	defer gen.RemoveTempFile(signaturePath)

	bodyPath, err := createEmptyTempFilePath()
	if err != nil {
		return fmt.Errorf("failed to create temp file for body - %v", err)
	}
	defer gen.RemoveTempFile(bodyPath)

	if _, err := runOpenSSLCommand(
		"asn1parse",
		"-in", documentPath,
		"-out", signaturePath,
		"-strparse", strconv.Itoa(signatureOffset),
		"-noout",
	); err != nil {
		return fmt.Errorf("failed to extract signature blob - %v", err)
	}

	if _, err := runOpenSSLCommand(
		"asn1parse",
		"-in", documentPath,
		"-out", bodyPath,
		"-strparse", "4",
		"-noout",
	); err != nil {
		return fmt.Errorf("failed to extract certificate body - %v", err)
	}

	verifyOutput, verifyErr := runOpenSSLCommand("sha512", "-verify", pubKeyPath, "-signature", signaturePath, bodyPath)
	if verifyErr != nil {
		return fmt.Errorf("failed to verify signature - %v", verifyErr)
	}
	if !strings.Contains(verifyOutput, "Verified OK") {
		return fmt.Errorf("signature verification did not return success: %s", verifyOutput)
	}

	return nil
}

// validateCertificateDateWindow verifies the certificate notBefore/notAfter window against current UTC time.
func validateCertificateDateWindow(certPath string) error {
	datesOutput, err := runOpenSSLCommand("x509", "-in", certPath, "-dates", "-noout")
	if err != nil {
		return fmt.Errorf("failed to read certificate dates - %v", err)
	}

	var notBeforeRaw string
	var notAfterRaw string
	for _, line := range strings.Split(datesOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "notBefore=") {
			notBeforeRaw = strings.TrimPrefix(line, "notBefore=")
		}
		if strings.HasPrefix(line, "notAfter=") {
			notAfterRaw = strings.TrimPrefix(line, "notAfter=")
		}
	}

	if notBeforeRaw == "" || notAfterRaw == "" {
		return fmt.Errorf("unable to parse notBefore/notAfter from certificate dates output")
	}

	notBefore, err := time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimSpace(notBeforeRaw))
	if err != nil {
		return fmt.Errorf("failed to parse notBefore date - %v", err)
	}
	notAfter, err := time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimSpace(notAfterRaw))
	if err != nil {
		return fmt.Errorf("failed to parse notAfter date - %v", err)
	}

	now := time.Now().UTC()
	if now.Before(notBefore.UTC()) {
		return fmt.Errorf("certificate is not yet valid (validity starts at %s)", strings.TrimSpace(notBeforeRaw))
	}
	if now.After(notAfter.UTC()) {
		return fmt.Errorf("certificate has expired (expired at %s)", strings.TrimSpace(notAfterRaw))
	}

	return nil
}

// validateCRLMetadata validates CRL issuer metadata and update window, and returns CRL text output.
func validateCRLMetadata(crlPath string) (string, error) {
	crlTextOutput, err := runCRLCommandWithDERFallback("-text", "-noout", "-in", crlPath)
	if err != nil {
		return "", fmt.Errorf("failed to parse CRL text - %v", err)
	}
	if !strings.Contains(crlTextOutput, "Issuer:") {
		return "", fmt.Errorf("CRL output does not contain issuer information")
	}
	if !strings.Contains(crlTextOutput, "Last Update:") || !strings.Contains(crlTextOutput, "Next Update:") {
		return "", fmt.Errorf("CRL output does not contain update timestamps")
	}

	dateOutput, err := runCRLCommandWithDERFallback("-noout", "-lastupdate", "-nextupdate", "-in", crlPath)
	if err != nil {
		return "", fmt.Errorf("failed to parse CRL validity window - %v", err)
	}

	var lastUpdateRaw string
	var nextUpdateRaw string
	for _, line := range strings.Split(dateOutput, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "lastUpdate=") {
			lastUpdateRaw = strings.TrimPrefix(line, "lastUpdate=")
		}
		if strings.HasPrefix(line, "nextUpdate=") {
			nextUpdateRaw = strings.TrimPrefix(line, "nextUpdate=")
		}
	}

	if lastUpdateRaw == "" || nextUpdateRaw == "" {
		return "", fmt.Errorf("CRL validity window is incomplete")
	}

	lastUpdate, err := time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimSpace(lastUpdateRaw))
	if err != nil {
		return "", fmt.Errorf("failed to parse CRL lastUpdate - %v", err)
	}
	nextUpdate, err := time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimSpace(nextUpdateRaw))
	if err != nil {
		return "", fmt.Errorf("failed to parse CRL nextUpdate - %v", err)
	}

	now := time.Now().UTC()
	if now.Before(lastUpdate.UTC()) {
		return "", fmt.Errorf("CRL is not yet valid (lastUpdate=%s)", strings.TrimSpace(lastUpdateRaw))
	}
	if now.After(nextUpdate.UTC()) {
		return "", fmt.Errorf("CRL has expired (nextUpdate=%s)", strings.TrimSpace(nextUpdateRaw))
	}

	return crlTextOutput, nil
}

// verifyCRLSignature verifies a CRL signature by extracting ASN.1 body/signature sections and checking with SHA-512.
func verifyCRLSignature(crlPath, ibmIntermediatePath string) error {
	pubKeyPath, err := createEmptyTempFilePath()
	if err != nil {
		return fmt.Errorf("failed to create temp file for CRL verification public key - %v", err)
	}
	defer gen.RemoveTempFile(pubKeyPath)

	if _, err := runOpenSSLCommand("x509", "-in", ibmIntermediatePath, "-pubkey", "-noout", "-out", pubKeyPath); err != nil {
		return fmt.Errorf("failed to extract public key from IBM intermediate certificate - %v", err)
	}

	asn1Output, useDER, err := runASN1ParseWithDERFallback(crlPath)
	if err != nil {
		return fmt.Errorf("failed to parse CRL ASN.1 structure - %v", err)
	}

	bodyBeginOffset, err := getSecondASN1Offset(asn1Output)
	if err != nil {
		return fmt.Errorf("failed to extract CRL body offset - %v", err)
	}
	signatureOffset, err := getLastASN1Offset(asn1Output)
	if err != nil {
		return fmt.Errorf("failed to extract CRL signature offset - %v", err)
	}

	signaturePath, err := createEmptyTempFilePath()
	if err != nil {
		return fmt.Errorf("failed to create temp file for CRL signature - %v", err)
	}
	defer gen.RemoveTempFile(signaturePath)

	bodyPath, err := createEmptyTempFilePath()
	if err != nil {
		return fmt.Errorf("failed to create temp file for CRL body - %v", err)
	}
	defer gen.RemoveTempFile(bodyPath)

	signatureArgs := []string{"asn1parse"}
	if useDER {
		signatureArgs = append(signatureArgs, "-inform", "DER")
	}
	signatureArgs = append(signatureArgs,
		"-in", crlPath,
		"-out", signaturePath,
		"-strparse", strconv.Itoa(signatureOffset),
		"-noout",
	)
	if _, err := runOpenSSLCommand(signatureArgs...); err != nil {
		return fmt.Errorf("failed to extract CRL signature blob - %v", err)
	}

	bodyArgs := []string{"asn1parse"}
	if useDER {
		bodyArgs = append(bodyArgs, "-inform", "DER")
	}
	bodyArgs = append(bodyArgs,
		"-in", crlPath,
		"-out", bodyPath,
		"-strparse", strconv.Itoa(bodyBeginOffset),
		"-noout",
	)
	if _, err := runOpenSSLCommand(bodyArgs...); err != nil {
		return fmt.Errorf("failed to extract CRL body blob - %v", err)
	}

	verifyOutput, verifyErr := runOpenSSLCommand("sha512", "-verify", pubKeyPath, "-signature", signaturePath, bodyPath)
	if verifyErr != nil {
		return fmt.Errorf("failed to verify CRL signature - %v", verifyErr)
	}
	if !strings.Contains(verifyOutput, "Verified OK") {
		return fmt.Errorf("CRL signature verification did not return success: %s", verifyOutput)
	}

	return nil
}

// extractCRLDistributionPointFromCertificate extracts the first CRL Distribution Point URI from a certificate.
func extractCRLDistributionPointFromCertificate(certPath string) (string, error) {
	output, err := runOpenSSLCommand("x509", "-in", certPath, "-noout", "-ext", "crlDistributionPoints")
	if err != nil {
		return "", fmt.Errorf("failed to read CRL distribution points - %v", err)
	}

	matches := crlURIRegex.FindStringSubmatch(output)
	if len(matches) != 2 {
		return "", fmt.Errorf("CRL distribution point URI not found")
	}

	return strings.TrimSpace(matches[1]), nil
}

// downloadCRLFromURLToTempFile downloads CRL content from http/https/file URL and stores it in a temporary binary file.
func downloadCRLFromURLToTempFile(crlURL string) (string, error) {
	parsedURL, err := url.Parse(crlURL)
	if err != nil {
		return "", fmt.Errorf("invalid CRL URL - %v", err)
	}

	var data []byte
	switch parsedURL.Scheme {
	case "http", "https":
		client := &http.Client{Timeout: opensslCommandTimeout}
		resp, err := client.Get(crlURL)
		if err != nil {
			return "", fmt.Errorf("failed to download CRL - %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return "", fmt.Errorf("failed to download CRL - unexpected HTTP status: %s", resp.Status)
		}
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read CRL response body - %v", err)
		}
	case "file":
		filePath := parsedURL.Path
		if filePath == "" {
			return "", fmt.Errorf("invalid file URL for CRL")
		}
		data, err = os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read CRL from file URL - %v", err)
		}
	default:
		return "", fmt.Errorf("unsupported CRL URL scheme: %s", parsedURL.Scheme)
	}

	if len(data) == 0 {
		return "", fmt.Errorf("downloaded CRL is empty")
	}

	crlPath, err := gen.CreateTempBinaryFile(data)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file for CRL - %v", err)
	}
	return crlPath, nil
}

// extractCertificateSerial extracts and normalizes the certificate serial number from OpenSSL output.
func extractCertificateSerial(certPath string) (string, error) {
	output, err := runOpenSSLCommand("x509", "-in", certPath, "-noout", "-serial")
	if err != nil {
		return "", fmt.Errorf("failed to extract certificate serial - %v", err)
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "serial=") {
			serial := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
			if serial == "" {
				break
			}
			return normalizeSerial(serial), nil
		}
	}
	return "", fmt.Errorf("serial not found in certificate output")
}

// isCertificateRevoked checks whether a normalized serial exists in the CRL text.
func isCertificateRevoked(crlText, serial string) bool {
	target := normalizeSerial(serial)
	if target == "" {
		return false
	}

	matches := serialRegex.FindAllStringSubmatch(crlText, -1)
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		if normalizeSerial(match[1]) == target {
			return true
		}
	}

	return strings.Contains(normalizeSerial(crlText), target)
}

// normalizeSerial removes non-hex characters and uppercases the serial for comparison.
func normalizeSerial(value string) string {
	var builder strings.Builder
	upper := strings.ToUpper(strings.TrimSpace(value))
	for _, r := range upper {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

// getLastASN1Offset returns the final ASN.1 node offset from openssl asn1parse output.
func getLastASN1Offset(asn1Output string) (int, error) {
	lines := strings.Split(asn1Output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		match := asn1OffsetPattern.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		offset, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, err
		}
		return offset, nil
	}
	return 0, fmt.Errorf("unable to determine ASN.1 offset from output")
}

// getSecondASN1Offset returns the second ASN.1 node offset from openssl asn1parse output.
func getSecondASN1Offset(asn1Output string) (int, error) {
	lines := strings.Split(asn1Output, "\n")
	offsets := make([]int, 0, 2)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		match := asn1OffsetPattern.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		offset, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, err
		}
		offsets = append(offsets, offset)
		if len(offsets) == 2 {
			return offsets[1], nil
		}
	}
	return 0, fmt.Errorf("unable to determine second ASN.1 offset from output")
}

// createEmptyTempFilePath creates and closes an empty temporary file, returning its path.
func createEmptyTempFilePath() (string, error) {
	tmpFile, err := os.CreateTemp("", gen.TempFolderNamePrefix)
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()
	return tmpFile.Name(), nil
}

// runOpenSSLCommand executes an OpenSSL command with timeout and returns combined output.
func runOpenSSLCommand(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opensslCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, gen.GetOpenSSLPath(), args...)
	output, err := cmd.CombinedOutput()
	trimmedOutput := strings.TrimSpace(string(output))

	if ctx.Err() == context.DeadlineExceeded {
		if trimmedOutput == "" {
			trimmedOutput = "openssl command timed out"
		}
		return trimmedOutput, errors.New(trimmedOutput)
	}

	if err != nil {
		if trimmedOutput == "" {
			trimmedOutput = err.Error()
		}
		return trimmedOutput, errors.New(trimmedOutput)
	}

	return trimmedOutput, nil
}

// runCRLCommandWithDERFallback runs openssl crl and retries with DER input when parsing fails.
func runCRLCommandWithDERFallback(args ...string) (string, error) {
	baseArgs := append([]string{"crl"}, args...)
	output, err := runOpenSSLCommand(baseArgs...)
	if err == nil {
		return output, nil
	}

	withDER := append([]string{"crl", "-inform", "DER"}, args...)
	outputDER, errDER := runOpenSSLCommand(withDER...)
	if errDER == nil {
		return outputDER, nil
	}

	if strings.TrimSpace(outputDER) != "" {
		return outputDER, errDER
	}
	return output, errDER
}

// runASN1ParseWithDERFallback runs openssl asn1parse and retries with DER input when parsing fails.
func runASN1ParseWithDERFallback(filePath string) (string, bool, error) {
	output, err := runOpenSSLCommand("asn1parse", "-in", filePath)
	if err == nil {
		return output, false, nil
	}

	outputDER, errDER := runOpenSSLCommand("asn1parse", "-inform", "DER", "-in", filePath)
	if errDER == nil {
		return outputDER, true, nil
	}

	if strings.TrimSpace(outputDER) != "" {
		return outputDER, false, errDER
	}
	return output, false, errDER
}

// stageError wraps an error detail with a validation stage prefix.
func stageError(stage, detail string) error {
	return fmt.Errorf("%s failed - %s", stage, strings.TrimSpace(detail))
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
		if strings.Contains(strings.ToLower(errMsg), "revoked") {
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
