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

package general

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	cert "github.com/ibm-hyper-protect/contract-go/encryption"
	sch "github.com/ibm-hyper-protect/contract-go/schema/contract"
	schn "github.com/ibm-hyper-protect/contract-go/schema/network"
)

const (
	TempFolderNamePrefix = "hpvs-"

	HyperProtectOsHpvs     = "hpvs"
	HyperProtectOsHpcrRhvs = "hpcr-rhvs"
)

type Contract struct {
	Env               string `yaml:"env"`
	Workload          string `yaml:"workload"`
	WorkloadSignature string `yaml:"envWorkloadSignature"`
}

// CheckIfEmpty - function to check if given arguments are not empty
func CheckIfEmpty(values ...interface{}) bool {
	empty := false

	for _, value := range values {
		if value == "" {
			empty = true
		}
	}

	return empty
}

// GetOpenSSLPath check if OPENSSL_BIN is set
// If set → returns its value
// If not set → defaults to "openssl"
func GetOpenSSLPath() string {
	if envPath := os.Getenv("OPENSSL_BIN"); envPath != "" {
		return envPath
	}
	return "openssl"
}

// ExecCommand - function to run os commands
func ExecCommand(commandName, stdinInput string, args ...string) (string, error) {
	cmd := exec.Command(commandName, args...)

	// Check for standard input
	if stdinInput != "" {
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			return "", err
		}
		defer stdinPipe.Close()

		go func() {
			defer stdinPipe.Close()
			stdinPipe.Write([]byte(stdinInput))
		}()
	}

	// Buffer to capture the output from the command.
	var out bytes.Buffer
	cmd.Stdout = &out

	// Run the command.
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Return the output from the command and nil for the error.
	return out.String(), nil
}

// ReadDataFromFile - function to read data from file
func ReadDataFromFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

// CreateTempFile - function to create temp file
func CreateTempFile(data string) (string, error) {
	trimmedData := strings.TrimSpace(data)
	tmpFile, err := os.CreateTemp("", TempFolderNamePrefix)
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Write the data to the temp file.
	_, err = tmpFile.WriteString(trimmedData)
	if err != nil {
		return "", err
	}

	// Return the path to the temp file.
	return tmpFile.Name(), nil
}

// RemoveTempFile - function to remove temp file
func RemoveTempFile(filePath string) error {
	return os.Remove(filePath)
}

// ListFoldersAndFiles - function to list files and folder under a folder
func ListFoldersAndFiles(folderPath string) ([]string, error) {
	var filesFoldersList []string

	contents, err := os.ReadDir(folderPath)
	if err != nil {
		return nil, err
	}

	for _, content := range contents {
		fullPath := filepath.Join(folderPath, content.Name())
		filesFoldersList = append(filesFoldersList, fullPath)
	}

	return filesFoldersList, nil
}

// CheckFileFolderExists - function to check if file or folder exists
func CheckFileFolderExists(folderFilePath string) bool {
	_, err := os.Stat(folderFilePath)
	return !os.IsNotExist(err)
}

// IsJSON - function to check if input data is JSON or not
func IsJSON(str string) bool {
	var js interface{}
	return json.Unmarshal([]byte(str), &js) == nil
}

// YamlToJson - function to convert YAML to JSON
func YamlToJson(str string) (string, error) {
	var obj interface{}

	err := yaml.Unmarshal([]byte(str), &obj)
	if err != nil {
		return "", err
	}

	jsonData, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	// Marshal the object to JSON
	return string(jsonData), err
}

// EncodeToBase64 - function to encode string as base64
func EncodeToBase64(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

// DecodeBase64String - function to decode base64 string
func DecodeBase64String(base64Data string) (string, error) {
	decodedData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return "", err
	}

	return string(decodedData), nil
}

// GenerateSha256 - function to generate SHA256 of a string
func GenerateSha256(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))

	hashedBytes := hasher.Sum(nil)

	return hex.EncodeToString(hashedBytes)
}

// MapToYaml - function to convert string map to YAML
func MapToYaml(m map[string]interface{}) (string, error) {
	// Marshal the map into a YAML string.
	yamlBytes, err := yaml.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(yamlBytes), nil
}

// KeyValueInjector - function to inject key value pair in YAML
func KeyValueInjector(contract, key, value string) (string, error) {
	yamlData := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(contract), &yamlData); err != nil {
		return "", fmt.Errorf("failed to parse contract - %v", err)
	}

	yamlData[key] = value

	modifiedYAMLBytes, err := yaml.Marshal(yamlData)
	if err != nil {
		return "", err
	}

	return string(modifiedYAMLBytes), nil
}

// CertificateDownloader - function to download encryption certificate
func CertificateDownloader(url string) (string, error) {
	// Send a GET request to the URL
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// GetEncryptPassWorkload - function to get encrypted password and encrypted workload from data
func GetEncryptPassWorkload(encryptedData string) (string, string) {
	return strings.Split(encryptedData, ".")[1], strings.Split(encryptedData, ".")[2]
}

// CheckUrlExists - function to check if URL exists or not
func CheckUrlExists(url string) (bool, error) {
	response, err := http.Head(url)
	if err != nil {
		return false, err
	}

	return response.StatusCode >= 200 && response.StatusCode < 300, nil
}

// GetDataFromLatestVersion - function to get the value based on constraints
func GetDataFromLatestVersion(jsonData, version string) (string, string, error) {
	var dataMap map[string]string
	if err := json.Unmarshal([]byte(jsonData), &dataMap); err != nil {
		return "", "", fmt.Errorf("error unmarshaling JSON data - %v", err)
	}

	targetConstraint, err := semver.NewConstraint(version)
	if err != nil {
		return "", "", fmt.Errorf("error parsing target version constraint - %v", err)
	}

	var matchingVersions []*semver.Version

	for versionStr := range dataMap {
		version, err := semver.NewVersion(versionStr)
		if err != nil {
			return "", "", fmt.Errorf("error parsing version - %v", err)
		}

		if targetConstraint.Check(version) {
			matchingVersions = append(matchingVersions, version)
		}
	}

	sort.Sort(sort.Reverse(semver.Collection(matchingVersions)))

	// Get the latest version and its corresponding data
	if len(matchingVersions) > 0 {
		latestVersion := matchingVersions[0]
		return latestVersion.String(), dataMap[latestVersion.String()], nil
	}

	// No matching version found
	return "", "", fmt.Errorf("no matching version found for the given constraint")
}

// FetchEncryptionCertificate - function to get encryption certificate
func FetchEncryptionCertificate(version, encryptionCertificate string) (string, error) {
	if version == "" {
		version = HyperProtectOsHpvs
	}

	if encryptionCertificate != "" {
		return encryptionCertificate, nil
	} else {
		if version == HyperProtectOsHpvs {
			return cert.EncryptionCertificateHpvs, nil
		} else if version == HyperProtectOsHpcrRhvs {
			return cert.EncryptionCertificateHpcrRhvs, nil
		} else {
			return "", fmt.Errorf("invalid Hyper Protect version")
		}
	}
}

// GenerateTgzBase64 - function to generate tgz and return it as base64
func GenerateTgzBase64(folderFilesPath []string) (string, error) {
	var buf bytes.Buffer

	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for _, path := range folderFilesPath {
		err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			relPath, err := filepath.Rel(filepath.Dir(path), filePath)
			if err != nil {
				return err
			}

			header, err := tar.FileInfoHeader(info, relPath)
			if err != nil {
				return err
			}
			header.Name = relPath

			if err := tw.WriteHeader(header); err != nil {
				return err
			}

			if !info.IsDir() {
				file, err := os.Open(filePath)
				if err != nil {
					return err
				}
				defer file.Close()

				if _, err := io.Copy(tw, file); err != nil {
					return err
				}
			}
			return nil
		})

		if err != nil {
			return "", err
		}
	}

	tw.Close()
	gw.Close()

	return EncodeToBase64(buf.Bytes()), nil
}

// VerifyContractWithSchema - function to verify if contract matches schema
func VerifyContractWithSchema(contract, version string) error {
	contractMap, err := stringToMap(contract)
	if err != nil {
		return fmt.Errorf("failed to convert to map %v", err)
	}
	contractStringMap := convertToStringkeys(contractMap)

	contractSchema, err := fetchContractSchema(version)
	if err != nil {
		return fmt.Errorf("error fetching contract schema")
	}

	sch, err := jsonschema.CompileString("schema.json", contractSchema)
	if err != nil {
		return fmt.Errorf("failed to parse schema - %v", err)
	}

	if err := sch.Validate(contractStringMap); err != nil {
		return fmt.Errorf("contract validation failed - %v", err)
	}

	return nil
}

// stringToMap - function to convert string contract to Map
func stringToMap(contract string) (map[any]any, error) {
	data := Contract{}

	err := yaml.Unmarshal([]byte(contract), &data)
	if err != nil {
		return nil, err
	}

	dataEnv := make(map[any]any)
	err = yaml.Unmarshal([]byte(data.Env), &dataEnv)
	if err != nil {
		return nil, err
	}

	dataWorkload := make(map[any]any)
	err = yaml.Unmarshal([]byte(data.Workload), &dataWorkload)
	if err != nil {
		return nil, err
	}

	dataMap := make(map[any]any)
	dataMap["env"] = dataEnv
	dataMap["workload"] = dataWorkload
	if len(data.WorkloadSignature) != 0 {
		dataMap["envWorkloadSignature"] = data.WorkloadSignature
	}

	return dataMap, err
}

// convertToStringkeys - function to convert any map to string map
func convertToStringkeys(m map[any]any) map[string]any {
	result := map[string]any{}
	for k, v := range m {
		switch v2 := v.(type) {
		case map[any]any:
			result[fmt.Sprint(k)] = convertToStringkeys(v2)
		default:
			result[fmt.Sprint(k)] = v
		}
	}
	return result
}

// fetchContractSchema - function that returns contract schema according to hyper protect version
func fetchContractSchema(version string) (string, error) {
	if version == HyperProtectOsHpvs || version == "" {
		return sch.ContractSchemaHpvs, nil
	} else if version == HyperProtectOsHpcrRhvs {
		return sch.ContractSchemaHpcrRhvs, nil
	} else {
		return "", fmt.Errorf("invalid Hyper Protect version")
	}
}

// VerifyNetworkSchema - function to validates a network-config YAML file
func VerifyNetworkSchema(Network_Config_File string) error {
	data, err := yamlParse(Network_Config_File)
	if err != nil {
		return fmt.Errorf("Invalid schema file %s: ", err)
	}
	sch, err := jsonschema.CompileString("schema.json", schn.NetworkSchema)
	if err != nil {
		return fmt.Errorf("failed to parse schema - %v", err)
	}

	if err := sch.Validate(data); err != nil {
		return fmt.Errorf("contract validation failed - %v", err)
	}

	return nil
}

// yamlParse - function to Parses and unmarshal a YAML file
func yamlParse(filename string) (map[string]any, error) {
	var yamlObj map[string]any
	if err := yaml.Unmarshal([]byte(filename), &yamlObj); err == nil {
		if json.Valid([]byte(filename)) {
			return nil, fmt.Errorf("error unmarshelling the YAML file")
		}
		return yamlObj, nil
	}
	return nil, fmt.Errorf("error unmarshelling the YAML file")
}
