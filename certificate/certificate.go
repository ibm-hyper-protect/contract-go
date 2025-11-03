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
func HpcrGetEncryptionCertificateFromJson(encryptionCertificateJson, version string) (string, map[string]string, error) {
	if gen.CheckIfEmpty(encryptionCertificateJson, version) {
		return "", nil, fmt.Errorf(missingParameterErrStatement)
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

	var vertCertMapVersion = make(map[string]map[string]string)
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

		msg, daysLeft, err := gen.CheckEncryptionCertValidity(cert, version)
		if err != nil {
			return "", err
		}
		fmt.Println("Encryption certificate validity status - ", msg)
		var verCertMap = make(map[string]string)
		verCertMap["encryption_certificate"] = cert
		verCertMap["encryption_cert_status"] = msg
		verCertMap["expiry_days"] = strconv.Itoa(daysLeft)
		vertCertMapVersion[version] = verCertMap
	}

	if formatType == formatJson {
		jsonBytes, err := json.Marshal(vertCertMapVersion)
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON - %v", err)
		}

		return string(jsonBytes), nil
	} else if formatType == formatYaml {
		yamlBytes, err := yaml.Marshal(vertCertMapVersion)
		if err != nil {
			return "", fmt.Errorf("failed to marshal YAML - %v", err)
		}
		return string(yamlBytes), nil
	} else {
		return "", fmt.Errorf("invalid output format")
	}
}

// HpcrEncryptionCertificatesValidation - checks encryption certificate validity for all given versions
func HpcrEncryptionCertificatesValidation(encryptionCert string) (string, int, error) {
	var certificates map[string]map[string]string
	if err := json.Unmarshal([]byte(encryptionCert), &certificates); err != nil {
		return "", 0, fmt.Errorf("failed to parse input JSON: %v", err)
	}

	if len(certificates) == 0 {
		return "", 0, fmt.Errorf("no encryption certificates found")
	}

	for version, certData := range certificates {
		cert, ok := certData["cert"]
		if !ok {
			return "", 0, fmt.Errorf("certificate missing for version %s", version)
		}

		msg, _, err := gen.CheckEncryptionCertValidity(cert, version)
		if err != nil {
			return "", 0, err
		}
		fmt.Println(msg)
	}
	return "", 0, nil
}
