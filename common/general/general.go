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
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	cert "github.com/ibm-hyper-protect/contract-go/v2/encryption"
	sch "github.com/ibm-hyper-protect/contract-go/v2/schema/contract"
	schn "github.com/ibm-hyper-protect/contract-go/v2/schema/network"
)

const (
	TempFolderNamePrefix = "hpvs-"

	HyperProtectOsHpvs                        = "hpvs"
	HyperProtectOsHpcrRhvs                    = "hpcr-rhvs"
	HyperProtectConfidentialContainerPeerPods = "hpcc-peerpod"
)

type Contract struct {
	Env               string `yaml:"env"`
	Workload          string `yaml:"workload"`
	WorkloadSignature string `yaml:"envWorkloadSignature"`
}

// CheckIfEmpty checks if any of the provided values are empty strings.
// It iterates through all provided arguments and returns true if at least one value is an empty string.
//
// Parameters:
//   - values: Variable number of interface{} values to check
//
// Returns:
//   - true if any value is an empty string, false otherwise
func CheckIfEmpty(values ...interface{}) bool {
	empty := false

	for _, value := range values {
		if value == "" {
			empty = true
		}
	}

	return empty
}

// GetOpenSSLPath returns the path to the OpenSSL binary.
// It checks the OPENSSL_BIN environment variable and returns its value if set.
// If the environment variable is not set, it defaults to "openssl" which uses the system PATH.
//
// Returns:
//   - Path to OpenSSL binary from OPENSSL_BIN environment variable, or "openssl" as default
func GetOpenSSLPath() string {
	if envPath := os.Getenv("OPENSSL_BIN"); envPath != "" {
		return envPath
	}
	return "openssl"
}

// ExecCommand executes a system command with optional stdin input and arguments.
// It runs the specified command, captures stdout output, and returns the result.
// If stdinInput is provided, it will be piped to the command's stdin.
//
// Parameters:
//   - commandName: Name or path of the command to execute
//   - stdinInput: Data to pipe to command's stdin (empty string for no stdin input)
//   - args: Variable number of command arguments
//
// Returns:
//   - Command stdout output as string
//   - Error if command execution fails
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

// ReadDataFromFile reads the entire contents of a file and returns it as a string.
// It opens the file, reads all data, and closes the file automatically.
//
// Parameters:
//   - filePath: Path to the file to read
//
// Returns:
//   - File contents as string
//   - Error if file cannot be opened or read
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

// CreateTempFile creates a temporary file with the provided data.
// It trims whitespace from the data, creates a temp file with the prefix "hpvs-",
// writes the data to it, and returns the file path.
//
// Parameters:
//   - data: String data to write to the temporary file
//
// Returns:
//   - Absolute path to the created temporary file
//   - Error if file creation or writing fails
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

// RemoveTempFile deletes a file at the specified path.
// It is typically used to clean up temporary files created by CreateTempFile.
//
// Parameters:
//   - filePath: Path to the file to delete
//
// Returns:
//   - Error if file deletion fails
func RemoveTempFile(filePath string) error {
	return os.Remove(filePath)
}

// ListFoldersAndFiles lists all files and subdirectories in a directory.
// It returns the full paths of all contents directly under the specified folder.
//
// Parameters:
//   - folderPath: Path to the directory to list
//
// Returns:
//   - Slice of full paths to all files and subdirectories
//   - Error if directory cannot be read
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

// CheckFileFolderExists checks whether a file or directory exists at the specified path.
// It uses os.Stat to determine existence without opening the file.
//
// Parameters:
//   - folderFilePath: Path to the file or directory to check
//
// Returns:
//   - true if the file or directory exists, false otherwise
func CheckFileFolderExists(folderFilePath string) bool {
	_, err := os.Stat(folderFilePath)
	return !os.IsNotExist(err)
}

// IsJSON validates whether a string contains valid JSON data.
// It attempts to unmarshal the string and returns true if successful.
//
// Parameters:
//   - str: String to validate as JSON
//
// Returns:
//   - true if the string is valid JSON, false otherwise
func IsJSON(str string) bool {
	var js interface{}
	return json.Unmarshal([]byte(str), &js) == nil
}

// YamlToJson converts a YAML string to JSON.
// It unmarshals the YAML data and then marshals it as JSON string.
//
// Parameters:
//   - str: YAML string to convert
//
// Returns:
//   - JSON string representation of the YAML data
//   - Error if YAML parsing or JSON marshaling fails
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

// EncodeToBase64 encodes binary data to Base64 string format.
// It uses standard Base64 encoding as defined in RFC 4648.
//
// Parameters:
//   - input: Byte array to encode
//
// Returns:
//   - Base64-encoded string
func EncodeToBase64(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

// DecodeBase64String decodes a Base64-encoded string to its original string form.
// It uses standard Base64 decoding as defined in RFC 4648.
//
// Parameters:
//   - base64Data: Base64-encoded string to decode
//
// Returns:
//   - Decoded string
//   - Error if Base64 decoding fails
func DecodeBase64String(base64Data string) (string, error) {
	decodedData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return "", err
	}

	return string(decodedData), nil
}

// GenerateSha256 generates a SHA-256 hash of a string.
// It returns the hash as a hexadecimal string representation.
//
// Parameters:
//   - input: String to hash
//
// Returns:
//   - SHA-256 hash as hexadecimal string
func GenerateSha256(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))

	hashedBytes := hasher.Sum(nil)

	return hex.EncodeToString(hashedBytes)
}

// MapToYaml converts a map to YAML format.
// It marshals the provided map structure into a YAML string.
//
// Parameters:
//   - m: Map with string keys to convert to YAML
//
// Returns:
//   - YAML string representation of the map
//   - Error if YAML marshaling fails
func MapToYaml(m map[string]interface{}) (string, error) {
	// Marshal the map into a YAML string.
	yamlBytes, err := yaml.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(yamlBytes), nil
}

// KeyValueInjector adds or updates a key-value pair in a YAML string.
// It parses the YAML contract, injects the new key-value pair, and returns the modified YAML.
//
// Parameters:
//   - contract: YAML string to modify
//   - key: Key to add or update
//   - value: Value to set for the key
//
// Returns:
//   - Modified YAML string with the injected key-value pair
//   - Error if YAML parsing or marshaling fails
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

// CertificateDownloader downloads a certificate from a URL.
// It sends an HTTP GET request to the specified URL and returns the response body.
//
// Parameters:
//   - url: URL to download the certificate from
//
// Returns:
//   - Certificate content as string
//   - Error if HTTP request fails or response cannot be read
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

// GetEncryptPassWorkload extracts the encrypted password and workload from encrypted data.
// It splits the encrypted data string in "hyper-protect-basic.<password>.<workload>" format
// and returns the password and workload components.
//
// Parameters:
//   - encryptedData: Encrypted data in "hyper-protect-basic.<password>.<workload>" format
//
// Returns:
//   - Encrypted password (Base64-encoded)
//   - Encrypted workload (Base64-encoded)
func GetEncryptPassWorkload(encryptedData string) (string, string) {
	return strings.Split(encryptedData, ".")[1], strings.Split(encryptedData, ".")[2]
}

// CheckUrlExists verifies if a URL is accessible by sending an HTTP HEAD request.
// It checks if the response status code is in the 2xx range (success).
//
// Parameters:
//   - url: URL to check
//
// Returns:
//   - true if URL returns 2xx status code, false otherwise
//   - Error if HTTP request fails
func CheckUrlExists(url string) (bool, error) {
	response, err := http.Head(url)
	if err != nil {
		return false, err
	}

	return response.StatusCode >= 200 && response.StatusCode < 300, nil
}

// GetDataFromLatestVersion retrieves the latest version data matching semantic version constraints.
// It parses JSON data containing version-keyed maps, applies version constraints,
// and returns the certificate for the latest matching version.
//
// Parameters:
//   - jsonData: JSON string containing version-to-data mappings
//   - version: Semantic version constraint (e.g., ">=1.1.0", "~1.1.14")
//
// Returns:
//   - Latest matching version string
//   - Certificate data for the matching version
//   - Error if JSON parsing, version constraint parsing, or no match found
func GetDataFromLatestVersion(jsonData, version string) (string, string, error) {
	var dataMap map[string]map[string]string
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
		return latestVersion.String(), dataMap[latestVersion.String()]["cert"], nil
	}

	// No matching version found
	return "", "", fmt.Errorf("no matching version found for the given constraint")
}

// FetchEncryptionCertificate retrieves the appropriate encryption certificate for a Hyper Protect platform.
// If a custom certificate is provided, it returns that. Otherwise, it returns the embedded default
// certificate for the specified platform version (hpvs, hpcr-rhvs, or hpcc-peerpod).
//
// Parameters:
//   - version: Hyper Protect platform version ("hpvs", "hpcr-rhvs", "hpcc-peerpod") - defaults to "hpvs" if empty
//   - encryptionCertificate: Custom encryption certificate (PEM format) - uses embedded default if empty
//
// Returns:
//   - Encryption certificate in PEM format
//   - Error if version is invalid
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
		} else if version == HyperProtectConfidentialContainerPeerPods {
			return cert.EncryptionCertificateHpccPeerPods, nil
		} else {
			return "", fmt.Errorf("invalid Hyper Protect version")
		}
	}
}

// GenerateTgzBase64 creates a compressed tar.gz archive from files and folders.
// It recursively archives all specified paths, compresses them with gzip,
// and returns the result as a Base64-encoded string.
//
// Parameters:
//   - folderFilesPath: Slice of file and folder paths to include in the archive
//
// Returns:
//   - Base64-encoded tar.gz archive
//   - Error if file reading, archiving, or compression fails
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

// VerifyContractWithSchema validates a contract against the schema for a specific Hyper Protect platform.
// It parses the contract YAML, retrieves the appropriate schema for the platform version,
// and validates the contract structure against that schema.
//
// Parameters:
//   - contract: Contract YAML string to validate
//   - version: Hyper Protect platform version ("hpvs", "hpcr-rhvs", "hpcc-peerpod") - defaults to "hpvs" if empty
//
// Returns:
//   - nil if contract is valid
//   - Error if contract parsing, schema retrieval, or validation fails
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

// stringToMap converts a contract YAML string to a nested map structure.
// It parses the contract YAML containing workload, env, and optional envWorkloadSignature fields,
// unmarshals each section, and returns a structured map representation.
//
// Parameters:
//   - contract: Contract YAML string with workload and env sections
//
// Returns:
//   - Map with "env", "workload", and optionally "envWorkloadSignature" keys
//   - Error if YAML unmarshaling fails
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

// convertToStringkeys recursively converts a map with any-typed keys to string-keyed maps.
// It traverses nested map structures and converts all keys to strings for JSON schema validation.
//
// Parameters:
//   - m: Map with any-typed keys to convert
//
// Returns:
//   - Map with string keys and recursively converted nested maps
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

// fetchContractSchema retrieves the embedded contract schema for a specific Hyper Protect platform.
// It returns the appropriate JSON schema string based on the platform version.
//
// Parameters:
//   - version: Hyper Protect platform version ("hpvs", "hpcr-rhvs", "hpcc-peerpod") - defaults to "hpvs" if empty
//
// Returns:
//   - JSON schema string for contract validation
//   - Error if version is invalid
func fetchContractSchema(version string) (string, error) {
	if version == HyperProtectOsHpvs || version == "" {
		return sch.ContractSchemaHpvs, nil
	} else if version == HyperProtectConfidentialContainerPeerPods {
		return sch.ContractSchemaHpvs, nil
	} else if version == HyperProtectOsHpcrRhvs {
		return sch.ContractSchemaHpcrRhvs, nil
	} else {
		return "", fmt.Errorf("invalid Hyper Protect version")
	}
}

// VerifyNetworkSchema validates a network configuration YAML against the network schema.
// It parses the network configuration YAML and validates it against the embedded network schema
// for on-premise Hyper Protect deployments.
//
// Parameters:
//   - Network_Config_File: Network configuration YAML string to validate
//
// Returns:
//   - nil if network configuration is valid
//   - Error if YAML parsing or schema validation fails
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
		return fmt.Errorf("network schema verification failed - %v", err)
	}

	return nil
}

// yamlParse parses and unmarshals a YAML string into a map.
// It validates that the input is valid YAML and not JSON format.
//
// Parameters:
//   - data: YAML string to parse
//
// Returns:
//   - Parsed YAML as a string-keyed map
//   - Error if YAML unmarshaling fails or input is JSON format
func yamlParse(data string) (map[string]any, error) {
	var yamlObj map[string]any
	if err := yaml.Unmarshal([]byte(data), &yamlObj); err == nil {
		if json.Valid([]byte(data)) {
			return nil, fmt.Errorf("error unmarshalling the YAML data")
		}
		return yamlObj, nil
	}
	return nil, fmt.Errorf("error unmarshalling the YAML data")
}

// CheckEncryptionCertValidity checks the validity status of an encryption certificate.
// It parses the certificate, calculates days until expiration, and returns status information.
// The status is "expired" if the certificate has expired, or "valid" otherwise.
//
// Parameters:
//   - encryptionCert: Encryption certificate in PEM format
//
// Returns:
//   - Certificate status ("valid" or "expired")
//   - Days until expiration (negative if expired)
//   - Expiry date in "DD-MM-YY HH:MM:SS GMT" format
//   - Error if PEM parsing or certificate parsing fails
func CheckEncryptionCertValidity(encryptionCert string) (string, int, string, error) {
	block, _ := pem.Decode([]byte(encryptionCert))
	if block == nil {
		return "", 0, "", fmt.Errorf("failed to parse PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to parse certificate %v", err)
	}

	now := time.Now()
	daysLeft := cert.NotAfter.Sub(now).Hours() / 24
	gmtTime := cert.NotAfter.UTC()
	formattedExpiryDays := gmtTime.Format("02-01-06 15:04:05") + " GMT"
	switch {
	case daysLeft < 0:
		return "expired", int(daysLeft), formattedExpiryDays, nil

	case daysLeft < 180:
		return "valid", int(daysLeft), formattedExpiryDays, nil

	default:
		return "valid", int(daysLeft), formattedExpiryDays, nil
	}
}

// CheckEncryptionCertValidityForContractEncryption validates an encryption certificate for contract encryption.
// It parses the certificate, checks expiration status, and returns appropriate messages.
// Returns an error if the certificate has already expired, or a warning if it expires within 180 days.
//
// Parameters:
//   - encryptionCert: Encryption certificate in PEM format
//
// Returns:
//   - Status message indicating validity, warning (< 180 days), or empty string if error
//   - Error if certificate has expired or PEM/certificate parsing fails
func CheckEncryptionCertValidityForContractEncryption(encryptionCert string) (string, error) {
	block, _ := pem.Decode([]byte(encryptionCert))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate %v", err)
	}

	now := time.Now()
	daysLeft := cert.NotAfter.Sub(now).Hours() / 24

	switch {
	case daysLeft < 0:
		return "", fmt.Errorf("Encryption certificate has already expired on %s",
			cert.NotAfter.Format("02-01-06 15:04:05"))

	case daysLeft < 180:
		return fmt.Sprintf("Warning: Encryption certificate will expire in %.0f days (on %s)",
			daysLeft, cert.NotAfter.Format("02-01-06 15:04:05")), nil

	default:
		return fmt.Sprintf("Encryption certificate is valid for another %.0f days (until %s)",
			daysLeft, cert.NotAfter.Format("02-01-06 15:04:05")), nil
	}
}
