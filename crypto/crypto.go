// Copyright (c) 2026 IBM Corp.
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

package crypto

import (
	"fmt"
	"net"
	"strings"

	enc "github.com/ibm-hyper-protect/contract-go/v2/common/encrypt"
	gen "github.com/ibm-hyper-protect/contract-go/v2/common/general"
)

// GenerateOpenSSLArtifacts generates RSA key or certificate artifacts using
// the openssl binary. All defaulting and validation must be performed by the
// applied here.
//
// Parameters:
//   - artifactType: Generation mode. Must be "key" or "cert".
//   - password:     Optional AES-256 passphrase for the private key(s).
//     Delivered to openssl via an anonymous fd pipe — never on the command line.
//     Pass an empty string to produce an unencrypted key.
//   - commonName:   X.509 subject CN for the client certificate.
//     Only used when artifactType == "cert". Must be pre-populated by caller.
//   - sans:         Comma-separated Subject Alternative Names,
//     e.g. "example.com,www.example.com,192.168.1.1".
//     Only used when artifactType == "cert". Must be pre-populated by caller.
//   - keySize:      RSA modulus size in bits. Must be 2048, 3072, or 4096.
//   - validDays:    Validity period in days.
//     For artifactType == "cert": certificate validity (must be > 0).
//     For artifactType == "key": must be 0; --days is not supported for key generation.
//
// Returns — for artifactType == "key":
//   - privateKeyPEM:    RSA private key in PEM format (write as <out>.pem, perm 0600)
//   - publicKeyPEM:     RSA public key PEM (write as <out>.pub.pem, perm 0644)
//   - privateKeySha:    SHA-256 of privateKeyPEM
//   - publicKeySha:     SHA-256 of publicKeyPEM
//   - caCertPEM, clientCertPEM, clientKeyPEM, caCertSha, clientCertSha, clientKeySha: empty strings
//
// Returns — for artifactType == "cert":
//   - caCertPEM:        Self-signed CA certificate in PEM format (write as <out>-ca.crt, perm 0644)
//   - clientCertPEM:    Client certificate signed by the CA in PEM format (write as <out>-client.crt, perm 0644)
//   - clientKeyPEM:     Client private key in PEM format (write as <out>-client.pem, perm 0600)
//   - caCertSha:        SHA-256 of caCertPEM
//   - clientCertSha:    SHA-256 of clientCertPEM
//   - clientKeySha:     SHA-256 of clientKeyPEM
//   - privateKeyPEM, publicKeyPEM, privateKeySha, publicKeySha: empty strings
//
// Returns an error if openssl is not found, inputs are invalid, or any step fails.
func GenerateOpenSSLArtifacts(artifactType, password, commonName, sans string, keySize, validDays int) (privateKeyPEM, publicKeyPEM, caCertPEM, clientCertPEM, clientKeyPEM, privateKeySha, publicKeySha, caCertSha, clientCertSha, clientKeySha string, err error) {
	if checkErr := enc.OpensslCheck(); checkErr != nil {
		err = fmt.Errorf("openssl not found - %v", checkErr)
		return
	}

	if artifactType != "key" && artifactType != "cert" {
		err = fmt.Errorf("invalid type: must be 'key' or 'cert'")
		return
	}
	if artifactType == "key" && validDays > 0 {
		err = fmt.Errorf("--days is not supported for --type key: key pairs do not carry an expiry; use --type cert to generate a certificate with a validity period")
		return
	}
	if keySize != 2048 && keySize != 3072 && keySize != 4096 {
		err = fmt.Errorf("invalid key size: must be 2048, 3072, or 4096")
		return
	}

	switch artifactType {
	case "key":
		privateKeyPEM, publicKeyPEM, err = generateKeyPair(keySize, password)
		if err != nil {
			privateKeyPEM = ""
			publicKeyPEM = ""
			err = fmt.Errorf("key generation failed - %w", err)
			return
		}
		privateKeySha = gen.GenerateSha256(privateKeyPEM)
		publicKeySha = gen.GenerateSha256(publicKeyPEM)
	case "cert":
		caCertPEM, clientCertPEM, clientKeyPEM, err = generateCertBundle(keySize, password, commonName, sans, validDays)
		if err != nil {
			caCertPEM = ""
			clientCertPEM = ""
			clientKeyPEM = ""
			err = fmt.Errorf("certificate generation failed - %w", err)
			return
		}
		caCertSha = gen.GenerateSha256(caCertPEM)
		clientCertSha = gen.GenerateSha256(clientCertPEM)
		clientKeySha = gen.GenerateSha256(clientKeyPEM)
	}
	return
}

// generateKeyPair produces an RSA private key and its public counterpart.
// Always returns a plain RSA public key PEM alongside the private key.
func generateKeyPair(keySize int, password string) (privateKeyPEM, publicKeyPEM string, err error) {
	plainKeyPEM, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "genrsa", fmt.Sprintf("%d", keySize))
	if err != nil {
		err = fmt.Errorf("failed to generate private key - %v", err)
		return
	}

	publicKeyPEM, err = enc.GeneratePublicKey(plainKeyPEM, "")
	if err != nil {
		err = fmt.Errorf("failed to extract public key - %v", err)
		return
	}

	// Encrypt the private key with the caller's password if one was provided.
	if password != "" {
		tmpPath, tmpErr := gen.CreateTempFile(plainKeyPEM)
		if tmpErr != nil {
			err = fmt.Errorf("failed to create temp file for key encryption - %v", tmpErr)
			return
		}
		defer gen.RemoveTempFile(tmpPath)

		args := []string{"rsa", "-aes256", "-passout", fmt.Sprintf("fd:%d", 3), "-in", tmpPath}
		privateKeyPEM, err = gen.ExecCommandWithPassword(gen.GetOpenSSLPath(), "", password, args...)
		if err != nil {
			err = fmt.Errorf("failed to encrypt private key - %v", err)
			return
		}
	} else {
		privateKeyPEM = plainKeyPEM
	}
	return
}

// generateCertBundle produces an ephemeral CA cert, a client private key,
// and a client certificate signed by that CA.
func generateCertBundle(keySize int, password, commonName, sans string, validDays int) (caCertPEM, clientCertPEM, clientKeyPEM string, err error) {
	// Step 1 — ephemeral CA key (never encrypted; not exposed to the caller)
	caKeyPEM, genErr := generatePrivateKey(keySize, "")
	if genErr != nil {
		err = fmt.Errorf("failed to generate CA key - %v", genErr)
		return
	}

	// Step 2 — self-signed CA certificate
	caCertPEM, genErr = generateSelfSignedCACert(caKeyPEM, validDays)
	if genErr != nil {
		err = fmt.Errorf("failed to generate CA certificate - %v", genErr)
		return
	}

	// Step 3 — client private key (encrypted if password is set)
	clientKeyPEM, genErr = generatePrivateKey(keySize, password)
	if genErr != nil {
		err = fmt.Errorf("failed to generate client key - %v", genErr)
		return
	}

	// Step 4 — client CSR
	csrPEM, genErr := generateCSR(clientKeyPEM, password, commonName, sans)
	if genErr != nil {
		err = fmt.Errorf("failed to generate client CSR - %v", genErr)
		return
	}

	// Step 5 — sign client CSR with CA
	clientCertPEM, genErr = signCSRWithCA(csrPEM, caCertPEM, caKeyPEM, validDays)
	if genErr != nil {
		err = fmt.Errorf("failed to sign client certificate - %v", genErr)
		return
	}
	return
}

// generatePrivateKey runs openssl genrsa to produce an RSA private key.
//
// OpenSSL 3.x genrsa rejects the combination of an encryption cipher flag and
// -passin in the same invocation. The correct two-step approach is:
//
//  1. Generate an unencrypted key: openssl genrsa <KeySize>
//  2. Re-encrypt with the passphrase via fd:3:
//     openssl rsa -aes256 -passout fd:3 -in <tmpFile>
//
// When password is empty the second step is skipped and the plain PEM is
// returned directly.
func generatePrivateKey(keySize int, password string) (string, error) {
	// Step 1 — always generate unencrypted
	plainKey, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "genrsa", fmt.Sprintf("%d", keySize))
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl genrsa - %v", err)
	}

	if password == "" {
		return plainKey, nil
	}

	// Step 2 — re-encrypt: openssl rsa -aes256 -passout fd:3 -in <tmpKey>
	tmpPath, err := gen.CreateTempFile(plainKey)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file for key encryption - %v", err)
	}
	defer gen.RemoveTempFile(tmpPath)

	args := []string{"rsa", "-aes256", "-passout", fmt.Sprintf("fd:%d", 3), "-in", tmpPath}
	encryptedKey, err := gen.ExecCommandWithPassword(gen.GetOpenSSLPath(), "", password, args...)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt private key - %v", err)
	}
	return encryptedKey, nil
}

// generateSelfSignedCACert produces a self-signed CA certificate valid for
// validDays days with the subject CN=CA.
func generateSelfSignedCACert(caKeyPEM string, validDays int) (string, error) {
	caKeyPath, err := gen.CreateTempFile(caKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}
	defer gen.RemoveTempFile(caKeyPath)

	caCert, err := gen.ExecCommand(gen.GetOpenSSLPath(), "", "req", "-x509", "-new",
		"-key", caKeyPath,
		"-subj", "/CN=CA",
		"-days", fmt.Sprintf("%d", validDays),
	)
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}
	return caCert, nil
}

// generateCSR creates a PKCS#10 certificate signing request for the client key.
// The passphrase (if any) is delivered via fd:3.
func generateCSR(clientKeyPEM, password, commonName, sans string) (string, error) {
	clientKeyPath, err := gen.CreateTempFile(clientKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}
	defer gen.RemoveTempFile(clientKeyPath)

	args := []string{"req", "-new", "-key", clientKeyPath}
	args = gen.AppendPasswordFdArgs(args, password)
	args = append(args,
		"-subj", fmt.Sprintf("/CN=%s", commonName),
		"-addext", fmt.Sprintf("subjectAltName=%s", buildSANExt(sans)),
	)

	csr, err := gen.ExecCommandWithPassword(gen.GetOpenSSLPath(), "", password, args...)
	if err != nil {
		return "", fmt.Errorf("failed to execute openssl command - %v", err)
	}
	return csr, nil
}

// signCSRWithCA signs the client CSR using the CA certificate and key.
// Reuses enc.CreateCert which already manages the temp files and .srl cleanup.
func signCSRWithCA(csrPEM, caCertPEM, caKeyPEM string, validDays int) (string, error) {
	csrPath, err := gen.CreateTempFile(csrPEM)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}
	defer gen.RemoveTempFile(csrPath)

	caCertPath, err := gen.CreateTempFile(caCertPEM)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}
	defer gen.RemoveTempFile(caCertPath)

	caKeyPath, err := gen.CreateTempFile(caKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file - %v", err)
	}
	defer gen.RemoveTempFile(caKeyPath)

	return enc.CreateCert(csrPath, caCertPath, caKeyPath, validDays)
}

// buildSANExt converts a comma-separated SAN string into the value expected
// by openssl's -addext flag.
//
// Each entry is auto-typed:
//
//	net.ParseIP(entry) != nil → "IP:<entry>"
//	otherwise                  → "DNS:<entry>"
//
// Example:
//
//	"example.com,127.0.0.1,*.internal" → "DNS:example.com,IP:127.0.0.1,DNS:*.internal"
func buildSANExt(sans string) string {
	entries := strings.Split(sans, ",")
	typed := make([]string, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if net.ParseIP(e) != nil {
			typed = append(typed, "IP:"+e)
		} else {
			typed = append(typed, "DNS:"+e)
		}
	}
	return strings.Join(typed, ",")
}
