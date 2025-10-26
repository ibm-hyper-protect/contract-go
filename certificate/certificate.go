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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"text/template"
	"time"

	gen "github.com/ibm-hyper-protect/contract-go/common/general"
	"gopkg.in/yaml.v3"
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

// HpcrGetEncryptionCertificateFromJson - function to get encryption certificate from encryption certificate JSON data
func HpcrGetEncryptionCertificateFromJson(encryptionCertificateJson, version string) (string, string, error) {
	if gen.CheckIfEmpty(encryptionCertificateJson, version) {
		return "", "", fmt.Errorf(missingParameterErrStatement)
	}

	return gen.GetDataFromLatestVersion(encryptionCertificateJson, version)
}

// HpcrDownloadEncryptionCertificates - function to download encryption certificates for specified versions
func HpcrDownloadEncryptionCertificates(versionList []string, formatType, certDownloadUrlTemplate string) (string, error) {
	if certDownloadUrlTemplate == "" {
		certDownloadUrlTemplate = defaultEncCertUrlTemplate
	}

	if formatType == "" {
		formatType = defaultFormat
	}

	if gen.CheckIfEmpty(versionList) {
		return "", fmt.Errorf(missingParameterErrStatement)
	}

	var verCertMap = make(map[string]string)

	for _, version := range versionList {
		verSpec := strings.Split(version, ".")

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

		verCertMap[version] = cert
	}

	if formatType == formatJson {
		jsonBytes, err := json.Marshal(verCertMap)
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON - %v", err)
		}

		return string(jsonBytes), nil
	} else if formatType == formatYaml {
		yamlBytes, err := yaml.Marshal(verCertMap)
		if err != nil {
			return "", fmt.Errorf("failed to marshal YAML - %v", err)
		}
		return string(yamlBytes), nil
	} else {
		return "", fmt.Errorf("invalid output format")
	}
}

// HpcrEncryptionCertificatesValidation - checks encryption certificate validity for all given versions
func HpcrEncryptionCertificatesValidation(certPEM string) (string, error) {
	var certMap map[string]string
	if err := json.Unmarshal([]byte(certPEM), &certMap); err != nil {
		return "", fmt.Errorf("failed to parse input JSON: %v", err)
	}

	if len(certMap) == 0 {
		return "", fmt.Errorf("No encryption certificate found")
	}

	var summary string

	for version, certString := range certMap {
		block, _ := pem.Decode([]byte(certString))
		if block == nil {
			msg := fmt.Sprintf("Failed to parse PEM block for version %s\n", version)
			fmt.Print(msg)
			summary += msg
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			msg := fmt.Sprintf("Failed to parse certificate for version %s: %v\n", version, err)
			fmt.Print(msg)
			summary += msg
			continue
		}

		now := time.Now()
		daysLeft := cert.NotAfter.Sub(now).Hours() / 24

		switch {
		case daysLeft < 0:
			msg := fmt.Sprintf("Certificate version %s has already expired on %s\n",
				version, cert.NotAfter.Format(time.RFC3339))
			fmt.Print(msg)
			summary += msg

		case daysLeft < 180:
			msg := fmt.Sprintf("Warning: Certificate version %s will expire in %.0f days (on %s)\n",
				version, daysLeft, cert.NotAfter.Format(time.RFC3339))
			fmt.Print(msg)
			summary += msg

		default:
			msg := fmt.Sprintf("Certificate version %s is valid for another %.0f days (until %s)\n",
				version, daysLeft, cert.NotAfter.Format(time.RFC3339))
			fmt.Print(msg)
			summary += msg
		}
	}

	fmt.Println("All certificates validated successfully.")
	return summary, nil
}
