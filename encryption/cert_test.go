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

package encryption

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// cccoSupportedModReleases is the number of mod releases kept at any time (n, n-1, n-2).
const cccoSupportedModReleases = 3

// newestCccoMod returns the newest mod release in the release map (entries are listed oldest first).
func newestCccoMod() CccoReleaseEntry {
	return CccoReleases[len(CccoReleases)-1]
}

// Testcase to check that exactly n, n-1, n-2 mod releases are kept and each has a certificate
func TestCccoModReleaseWindow(t *testing.T) {
	assert.Len(t, CccoReleases, cccoSupportedModReleases)
	for _, r := range CccoReleases {
		assert.NotEmpty(t, CertificateMap[OsTypeCcco][r.Mod], "missing cert for mod %s", r.Mod)
	}
}

// Testcase to check that every fixpack resolves to the certificate of its parent mod release
func TestCccoFixpackSharesParentCert(t *testing.T) {
	fixpacks := 0
	for _, r := range CccoReleases {
		for _, fp := range r.Fixpacks {
			fixpacks++
			assert.Equal(t, CertificateMap[OsTypeCcco][r.Mod], CertificateMap[OsTypeCcco][fp], "fixpack %s must use the cert of %s", fp, r.Mod)
		}
	}
	assert.NotZero(t, fixpacks, "release map should declare at least one fixpack")
}

// Testcase to check that undeclared and legacy date-based versions are rejected
func TestCccoUndeclaredVersionsRejected(t *testing.T) {
	newest := newestCccoMod()
	undeclared := []string{
		newest.Mod + ".99",            // fixpack that is not declared
		"99.99.99",                    // mod release that is not declared
		"26.7.1", "26.4.0", "25.12.0", // legacy date-based versions
	}
	for _, v := range undeclared {
		_, ok := CertificateMap[OsTypeCcco][v]
		assert.False(t, ok, "version %s should not be accepted", v)
	}
}

// Testcase to check that the default CCCO certificate is the newest mod release certificate
func TestCccoLatestCertIsNewestMod(t *testing.T) {
	assert.Equal(t, CertificateMap[OsTypeCcco][newestCccoMod().Mod], LatestEncryptionCertificateCcco)
}

// Testcase to check that release-map entries are well formed: fixpacks (x.x.x.x) belong to their parent mod (x.x.x)
func TestCccoReleaseMapWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range CccoReleases {
		assert.Len(t, strings.Split(r.Mod, "."), 3, "mod %s must be x.x.x", r.Mod)
		assert.False(t, seen[r.Mod], "duplicate version %s", r.Mod)
		seen[r.Mod] = true
		for _, fp := range r.Fixpacks {
			assert.Len(t, strings.Split(fp, "."), 4, "fixpack %s must be x.x.x.x", fp)
			assert.True(t, strings.HasPrefix(fp, r.Mod+"."), "fixpack %s must belong to mod %s", fp, r.Mod)
			assert.False(t, seen[fp], "duplicate version %s", fp)
			seen[fp] = true
		}
	}
}

// Testcase to check that the release map is ordered oldest first, as the listing relies on it
func TestCccoReleaseMapOrderedOldestFirst(t *testing.T) {
	for i := 1; i < len(CccoReleases); i++ {
		assert.Equal(t, 1, CompareVersions(CccoReleases[i].Mod, CccoReleases[i-1].Mod), "%s must be newer than %s", CccoReleases[i].Mod, CccoReleases[i-1].Mod)
	}
}

// Testcase to check that mod releases carry distinct certificates, except for placeholders
func TestCccoModCertsAreDistinctFromNewest(t *testing.T) {
	newest := newestCccoMod()
	previous := CccoReleases[len(CccoReleases)-2]
	assert.NotEqual(t, CertificateMap[OsTypeCcco][previous.Mod], CertificateMap[OsTypeCcco][newest.Mod])
}
