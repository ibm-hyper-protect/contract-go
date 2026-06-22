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

package encryption

import (
	"embed"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// OS type constants for certificate management
const (
	OsTypeCcrt = "ccrt"
	OsTypeCcrv = "ccrv"
	OsTypeCcco = "ccco"
	OsTypeHpvs = "hpvs"
)

// Embed all certificate directories
//
//go:embed ccrt/*.crt
//go:embed ccrv/*.crt
//go:embed ccco/*.crt
//go:embed hpvs/*.crt
var certFS embed.FS

// CertificateMap holds the mapping of OS type and version to certificate content.
// This map is automatically populated from embedded certificate files.
var CertificateMap map[string]map[string]string

// Latest encryption certificate variables - populated automatically with latest versions
var (
	LatestEncryptionCertificateCcrt string
	LatestEncryptionCertificateCcrv string
	LatestEncryptionCertificateCcco string
	LatestEncryptionCertificateHpvs string
)

var initOnce sync.Once

// init automatically discovers and loads all embedded certificates
func init() {
	initOnce.Do(func() {
		CertificateMap = make(map[string]map[string]string)

		// Initialize maps for each OS type
		CertificateMap[OsTypeCcrt] = make(map[string]string)
		CertificateMap[OsTypeCcrv] = make(map[string]string)
		CertificateMap[OsTypeCcco] = make(map[string]string)
		CertificateMap[OsTypeHpvs] = make(map[string]string)

		// Load certificates from each directory
		loadCertificatesFromDir(OsTypeCcrt)
		loadCertificatesFromDir(OsTypeCcrv)
		loadCertificatesFromDir(OsTypeCcco)
		loadCertificatesFromDir(OsTypeHpvs)

		// Set latest certificate variables
		LatestEncryptionCertificateCcrt = getLatestCertificate(OsTypeCcrt)
		LatestEncryptionCertificateCcrv = getLatestCertificate(OsTypeCcrv)
		LatestEncryptionCertificateCcco = getLatestCertificate(OsTypeCcco)
		LatestEncryptionCertificateHpvs = getLatestCertificate(OsTypeHpvs)
	})
}

// loadCertificatesFromDir loads all certificates from a specific directory
func loadCertificatesFromDir(osType string) {
	entries, err := certFS.ReadDir(osType)
	if err != nil {
		// Directory doesn't exist or can't be read, skip
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}

		// Extract version from filename
		version := extractVersionFromFilename(entry.Name())
		if version == "" {
			continue
		}

		// Read certificate content
		certPath := filepath.Join(osType, entry.Name())
		content, err := certFS.ReadFile(certPath)
		if err != nil {
			continue
		}

		// Store in map
		CertificateMap[osType][version] = string(content)
	}
}

// extractVersionFromFilename extracts the version number from a certificate filename.
// Supports patterns like:
//   - ibm-hyper-protect-container-runtime-26.2.0-encrypt.crt -> 26.2.0
//   - ibm-confidential-computing-container-runtime-rhvs-26.4.1-encrypt.crt -> 26.4.1
//   - ibm-hyper-protect-confidential-container-25.12.0-encrypt.crt -> 25.12.0
//   - ibm-hyper-protect-container-runtime-1-0-s390x-28-encrypt.crt -> 1.0.28
func extractVersionFromFilename(filename string) string {
	// Pattern to match semantic version (X.Y.Z or X.Y.Z.W)
	re := regexp.MustCompile(`(\d+\.\d+\.\d+(?:\.\d+)?)-encrypt\.crt$`)
	matches := re.FindStringSubmatch(filename)
	if len(matches) > 1 {
		return matches[1]
	}

	// Pattern to match HPVS format: ibm-hyper-protect-container-runtime-1-0-s390x-XX-encrypt.crt
	// where XX is the version number
	reHpvs := regexp.MustCompile(`runtime-(\d+)-(\d+)-s390x-(\d+)-encrypt\.crt$`)
	matches = reHpvs.FindStringSubmatch(filename)
	if len(matches) > 1 {
		version := fmt.Sprintf("%s.%s.%s", matches[1], matches[2], matches[3])
		return version
	}

	return ""
}

// getLatestCertificate returns the certificate content for the latest version of an OS type.
// It uses semantic versioning to determine the latest version.
func getLatestCertificate(osType string) string {
	osMap, exists := CertificateMap[osType]
	if !exists || len(osMap) == 0 {
		return ""
	}

	// Find the latest version using simple version comparison
	var latestVersion string
	for version := range osMap {
		if latestVersion == "" || CompareVersions(version, latestVersion) > 0 {
			latestVersion = version
		}
	}

	return osMap[latestVersion]
}

// CompareVersions compares two semantic version strings.
// Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if equal
func CompareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		if i < len(parts1) {
			fmt.Sscanf(parts1[i], "%d", &p1)
		}
		if i < len(parts2) {
			fmt.Sscanf(parts2[i], "%d", &p2)
		}

		if p1 > p2 {
			return 1
		} else if p1 < p2 {
			return -1
		}
	}

	return 0
}
